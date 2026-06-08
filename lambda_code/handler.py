"""
MCP Server Lambda Handler - Windows Instance Diagnostics via SSM.

A general-purpose read-only MCP server that allows AWS DevOps Agent to
investigate Windows EC2 instances via SSM RunCommand. Supports querying
event logs, service status, system info, and running arbitrary read-only
PowerShell commands (verb-allowlisted).
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import boto3

# --- Configuration ---
ALLOWED_INSTANCE_IDS_PARAM = os.environ.get("ALLOWED_INSTANCE_IDS_PARAM", "/mcp-server/allowed-instance-ids")
SSM_COMMAND_TIMEOUT = int(os.environ.get("SSM_COMMAND_TIMEOUT", "30"))
MAX_OUTPUT_CHARS = int(os.environ.get("MAX_OUTPUT_CHARS", "10000"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# --- Logging ---
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# --- AWS Clients ---
_ssm_clients: dict = {}  # Cache regional SSM clients


def _get_ssm_client(region: str | None = None):
    """Get or create a regional SSM client. Defaults to Lambda's own region."""
    region = region or os.environ.get("AWS_REGION", "eu-west-1")
    if region not in _ssm_clients:
        _ssm_clients[region] = boto3.client("ssm", region_name=region)
    return _ssm_clients[region]

# --- Cache for allowed instance IDs ---
_allowed_ids_cache: dict = {"ids": None, "expires": 0}
CACHE_TTL = 300  # 5 minutes

# --- PowerShell Verb Allowlist ---
# Only read-only / diagnostic verbs are permitted
ALLOWED_VERBS = frozenset([
    "get", "test", "select", "format", "measure",
    "convertto", "convertfrom", "compare", "find",
    "resolve", "trace", "debug", "where", "sort",
    "group", "out",
])

# Explicitly blocked commands even if verb matches
BLOCKED_COMMANDS = frozenset([
    "get-credential",
    "get-secret",
    "convertto-securestring",
])

# Blocked patterns in arguments (prevent data exfiltration / writes)
BLOCKED_ARGUMENT_PATTERNS = [
    re.compile(r"\b(invoke-webrequest|invoke-restmethod|iwr|irm|curl|wget)\b", re.IGNORECASE),
    re.compile(r"\b(start-process|new-item|remove-item|set-item|rename-item)\b", re.IGNORECASE),
    re.compile(r"\b(out-file|export-csv|export-clixml|set-content|add-content)\b", re.IGNORECASE),
    re.compile(r"\b(send-mailmessage|new-psdrive)\b", re.IGNORECASE),
    re.compile(r"\b(stop-|start-|restart-|suspend-|resume-)(process|service|computer)\b", re.IGNORECASE),
    re.compile(r"\b(remove-|delete-|clear-|reset-)\w+", re.IGNORECASE),
    re.compile(r"[|;`]\s*(remove|stop|start|restart|set|new|invoke|send)", re.IGNORECASE),
]


def _get_allowed_instance_ids() -> set[str]:
    """Retrieve allowed instance IDs from SSM Parameter Store with caching."""
    now = time.time()
    if _allowed_ids_cache["ids"] is not None and now < _allowed_ids_cache["expires"]:
        return _allowed_ids_cache["ids"]

    try:
        client = _get_ssm_client()  # Parameter Store is always in Lambda's region
        response = client.get_parameter(Name=ALLOWED_INSTANCE_IDS_PARAM)
        raw = response["Parameter"]["Value"]
        ids = {i.strip() for i in raw.split(",") if i.strip()}
        _allowed_ids_cache["ids"] = ids
        _allowed_ids_cache["expires"] = now + CACHE_TTL
        return ids
    except Exception as e:
        logger.error(f"Failed to fetch allowed instance IDs: {e}")
        if _allowed_ids_cache["ids"] is not None:
            return _allowed_ids_cache["ids"]
        return set()


def _validate_instance_id(instance_id: str) -> str | None:
    """Validate instance ID format and allowlist. Returns error message or None."""
    if not instance_id or not isinstance(instance_id, str):
        return "instance_id is required and must be a string"
    if not re.match(r"^i-[0-9a-f]{8,17}$", instance_id):
        return f"Invalid instance ID format: {instance_id}"
    allowed = _get_allowed_instance_ids()
    if instance_id not in allowed:
        return f"Instance {instance_id} is not in the allowlist"
    return None


def _validate_powershell_command(command: str) -> str | None:
    """
    Validate a PowerShell command against the verb allowlist.
    Returns error message or None if safe.
    """
    if not command or not command.strip():
        return "Command cannot be empty"

    # Check for blocked argument patterns anywhere in the command
    for pattern in BLOCKED_ARGUMENT_PATTERNS:
        if pattern.search(command):
            return f"Command contains blocked pattern: {pattern.pattern}"

    # Extract the primary cmdlet (first token, or first token after pipeline segments)
    # We validate ALL cmdlets in the pipeline
    # Split on pipe and semicolons to check each segment
    segments = re.split(r"[|;]", command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        # Get the first token (the cmdlet)
        cmdlet = segment.split()[0].strip().lower() if segment.split() else ""

        # Skip variable assignments, comments, etc.
        if cmdlet.startswith("$") or cmdlet.startswith("#"):
            continue

        # Check if it's a Verb-Noun format
        if "-" in cmdlet:
            verb = cmdlet.split("-")[0]
            if verb not in ALLOWED_VERBS:
                return f"Verb '{verb}' is not in the allowlist. Allowed: {', '.join(sorted(ALLOWED_VERBS))}"
            if cmdlet in BLOCKED_COMMANDS:
                return f"Command '{cmdlet}' is explicitly blocked"

    return None


# --- SSM Execution ---

def _run_ssm_command(instance_id: str, command: str, region: str | None = None) -> dict:
    """Execute a PowerShell command via SSM and return the output."""
    ssm = _get_ssm_client(region)
    try:
        send_response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=SSM_COMMAND_TIMEOUT,
        )
        command_id = send_response["Command"]["CommandId"]
    except ssm.exceptions.InvalidInstanceId:
        return {"success": False, "output": f"Instance {instance_id} is not reachable via SSM. Check SSM Agent status and IAM instance profile."}
    except Exception as e:
        return {"success": False, "output": f"Failed to send SSM command: {str(e)}"}

    # Poll for completion
    deadline = time.time() + SSM_COMMAND_TIMEOUT + 5
    while time.time() < deadline:
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = result["Status"]
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                break
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(1)
            continue
        time.sleep(1)
    else:
        return {"success": False, "output": "TIMEOUT: SSM command did not complete within the allowed time."}

    output = result.get("StandardOutputContent", "")
    error_output = result.get("StandardErrorContent", "")

    if status == "TimedOut":
        truncated = output[:MAX_OUTPUT_CHARS] if output else ""
        return {"success": False, "output": f"TIMEOUT: Command timed out.\nPartial output:\n{truncated}"}

    if status != "Success":
        return {"success": False, "output": f"Command failed (status={status}).\nStderr:\n{error_output}\nStdout:\n{output}"}

    # Truncate if needed
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + f"\n\n[TRUNCATED: Output exceeded {MAX_OUTPUT_CHARS} characters]"

    return {"success": True, "output": output}


# --- Tool Definitions ---

TOOLS = [
    {
        "name": "run_powershell_command",
        "description": (
            "Execute a read-only PowerShell command on a Windows EC2 instance via SSM. "
            "Only commands starting with allowed verbs are permitted: Get-, Test-, Select-, "
            "Format-, Measure-, ConvertTo-, ConvertFrom-, Compare-, Find-, Resolve-, Trace-, "
            "Debug-, Where-, Sort-, Group-, Out-. "
            "Pipeline commands are supported (e.g., 'Get-Process | Sort-Object CPU -Descending'). "
            "Write operations, process management, and network calls are blocked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "EC2 instance ID of the target Windows instance (e.g., i-0abc123def456)",
                },
                "command": {
                    "type": "string",
                    "description": (
                        "PowerShell command to execute. Must use allowed read-only verbs. "
                        "Examples: 'Get-EventLog -LogName System -Newest 50', "
                        "'Get-Service | Where-Object Status -eq Running', "
                        "'Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10'"
                    ),
                },
                "region": {
                    "type": "string",
                    "description": "AWS region where the instance resides (e.g., 'us-east-1', 'eu-west-1'). Defaults to the MCP server's region if omitted.",
                },
            },
            "required": ["instance_id", "command"],
        },
    },
    {
        "name": "get_windows_event_logs",
        "description": (
            "Query Windows Event Logs from an EC2 instance. Retrieves entries from any "
            "event log (Application, System, Security, or custom logs like "
            "'Microsoft-Windows-CertificationAuthority/Admin'). Supports filtering by "
            "level, source provider, and time range."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "EC2 instance ID of the target Windows instance",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region where the instance resides. Defaults to the MCP server's region if omitted.",
                },
                "log_name": {
                    "type": "string",
                    "description": "Event log name (e.g., 'Application', 'System', 'Security', 'Microsoft-Windows-CertificationAuthority/Admin')",
                    "default": "Application",
                },
                "max_events": {
                    "type": "integer",
                    "description": "Maximum number of events to return (default: 50, max: 200)",
                    "default": 50,
                },
                "hours_back": {
                    "type": "integer",
                    "description": "How many hours back to search (default: 24, max: 168)",
                    "default": 24,
                },
                "level": {
                    "type": "string",
                    "enum": ["all", "critical", "error", "warning", "information"],
                    "description": "Minimum severity level to return",
                    "default": "all",
                },
                "source": {
                    "type": "string",
                    "description": "Filter by source/provider name (optional, e.g., 'Microsoft-Windows-CertificationAuthority')",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "get_windows_services",
        "description": (
            "Check the status of Windows services on an EC2 instance. "
            "Can query specific services by name or list all services with optional status filter."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "EC2 instance ID of the target Windows instance",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region where the instance resides. Defaults to the MCP server's region if omitted.",
                },
                "service_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific service names to check (e.g., ['CertSvc', 'W3SVC', 'MSSQLSERVER']). If omitted, returns all services.",
                },
                "status_filter": {
                    "type": "string",
                    "enum": ["all", "running", "stopped"],
                    "description": "Filter services by status (default: all)",
                    "default": "all",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "get_system_info",
        "description": (
            "Get system information from a Windows EC2 instance including OS version, "
            "uptime, hostname, CPU/memory usage, disk space, and network configuration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "EC2 instance ID of the target Windows instance",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region where the instance resides. Defaults to the MCP server's region if omitted.",
                },
            },
            "required": ["instance_id"],
        },
    },
]


# --- Tool Command Builders ---

def _build_event_logs_command(arguments: dict) -> str:
    """Build PowerShell command for event log retrieval."""
    log_name = arguments.get("log_name", "Application")
    max_events = min(int(arguments.get("max_events", 50)), 200)
    hours_back = min(int(arguments.get("hours_back", 24)), 168)
    level = arguments.get("level", "all")
    source = arguments.get("source", "")

    # Sanitize log_name — only allow alphanumeric, hyphens, slashes, spaces
    if not re.match(r"^[\w\s\-/]+$", log_name):
        return None

    # Build XPath filter
    conditions = []
    if level != "all":
        level_map = {"critical": 1, "error": 2, "warning": 3, "information": 4}
        conditions.append(f"Level={level_map[level]}")

    time_filter = f"TimeCreated[@SystemTime>='{{{hours_back}}}']"

    xpath_parts = []
    if source:
        # Sanitize source
        if not re.match(r"^[\w\s\-\.]+$", source):
            return None
        xpath_parts.append(f"Provider[@Name='{source}']")

    xpath_parts.append(time_filter)
    if conditions:
        xpath_parts.extend(conditions)

    xpath = "*[System[" + " and ".join(xpath_parts) + "]]"

    return (
        f"$start = (Get-Date).AddHours(-{hours_back}).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ');\n"
        f"$xpath = \"*[System["
        + (f"Provider[@Name='{source}'] and " if source else "")
        + f"TimeCreated[@SystemTime>='$start']"
        + (f" and Level={level_map[level]}" if level != 'all' else "")
        + f"]]\";\n"
        f"Get-WinEvent -LogName '{log_name}' -FilterXPath $xpath -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
        f"Format-List TimeCreated, Id, LevelDisplayName, ProviderName, Message"
    )


def _build_services_command(arguments: dict) -> str:
    """Build PowerShell command for service status check."""
    service_names = arguments.get("service_names", [])
    status_filter = arguments.get("status_filter", "all")

    # Sanitize service names
    if service_names:
        for name in service_names:
            if not re.match(r"^[\w\-\.]+$", name):
                return None
        names_str = ",".join(f"'{n}'" for n in service_names)
        cmd = f"Get-Service -Name {names_str} -ErrorAction SilentlyContinue"
    else:
        cmd = "Get-Service"

    if status_filter == "running":
        cmd += " | Where-Object Status -eq 'Running'"
    elif status_filter == "stopped":
        cmd += " | Where-Object Status -eq 'Stopped'"

    cmd += " | Format-Table Name, DisplayName, Status, StartType -AutoSize"
    return cmd


def _build_system_info_command() -> str:
    """Build PowerShell command for system information."""
    return """
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

Write-Output "=== SYSTEM INFO ==="
Write-Output "Hostname: $($cs.Name)"
Write-Output "Domain: $($cs.Domain)"
Write-Output "OS: $($os.Caption) $($os.Version)"
Write-Output "Last Boot: $($os.LastBootUpTime)"
Write-Output "Uptime: $((Get-Date) - $os.LastBootUpTime)"

Write-Output "`n=== CPU & MEMORY ==="
Write-Output "CPU: $($cpu.Name)"
Write-Output "Cores: $($cs.NumberOfLogicalProcessors)"
Write-Output "Total RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB"
Write-Output "Free RAM: $([math]::Round($os.FreePhysicalMemory / 1MB, 2)) GB"
Write-Output "Memory Usage: $([math]::Round((1 - $os.FreePhysicalMemory * 1024 / $os.TotalVisibleMemorySize) * 100, 1))%"

Write-Output "`n=== DISK SPACE ==="
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $free = [math]::Round($_.FreeSpace / 1GB, 2)
    $total = [math]::Round($_.Size / 1GB, 2)
    $used = [math]::Round(($_.Size - $_.FreeSpace) / $_.Size * 100, 1)
    Write-Output "$($_.DeviceID) $free GB free / $total GB total ($used% used)"
}

Write-Output "`n=== NETWORK ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1' | Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize
""".strip()


# --- Tool Execution ---

def _execute_tool(tool_name: str, arguments: dict) -> dict:
    """Execute a tool and return the MCP result."""
    instance_id = arguments.get("instance_id", "")
    region = arguments.get("region")  # None means use Lambda's own region

    # Validate region format if provided
    if region and not re.match(r"^[a-z]{2}-[a-z]+-\d$", region):
        return {"content": [{"type": "text", "text": f"Invalid region format: {region}"}], "isError": True}

    # Validate instance
    error = _validate_instance_id(instance_id)
    if error:
        return {"content": [{"type": "text", "text": error}], "isError": True}

    # Build or validate command
    if tool_name == "run_powershell_command":
        command = arguments.get("command", "")
        error = _validate_powershell_command(command)
        if error:
            return {"content": [{"type": "text", "text": f"Command rejected: {error}"}], "isError": True}

    elif tool_name == "get_windows_event_logs":
        command = _build_event_logs_command(arguments)
        if not command:
            return {"content": [{"type": "text", "text": "Invalid parameters for event log query (check log_name and source format)"}], "isError": True}

    elif tool_name == "get_windows_services":
        command = _build_services_command(arguments)
        if not command:
            return {"content": [{"type": "text", "text": "Invalid service name format (alphanumeric, hyphens, dots only)"}], "isError": True}

    elif tool_name == "get_system_info":
        command = _build_system_info_command()

    else:
        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}

    # Execute via SSM
    start_time = time.time()
    result = _run_ssm_command(instance_id, command, region=region)
    duration_ms = int((time.time() - start_time) * 1000)

    # Structured log
    logger.info(json.dumps({
        "tool_name": tool_name,
        "instance_id": instance_id,
        "region": region or os.environ.get("AWS_REGION", "unknown"),
        "duration_ms": duration_ms,
        "success": result["success"],
    }))

    # Format output with metadata
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    region_display = region or os.environ.get("AWS_REGION", "local")
    header = f"[Instance: {instance_id} | Region: {region_display} | Tool: {tool_name} | Time: {timestamp} | Duration: {duration_ms}ms]\n{'=' * 60}\n"
    output_text = header + result["output"]

    return {
        "content": [{"type": "text", "text": output_text}],
        "isError": not result["success"],
    }


# --- MCP Protocol ---

SERVER_INFO = {
    "name": "windows-instance-diagnostics",
    "version": "1.0.0",
}

SERVER_CAPABILITIES = {
    "tools": {"listChanged": False},
}


def _handle_initialize(params: dict) -> dict:
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": SERVER_CAPABILITIES,
        "serverInfo": SERVER_INFO,
    }


def _handle_tools_list(params: dict) -> dict:
    return {"tools": TOOLS}


def _handle_tools_call(params: dict) -> dict:
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    tool_def = next((t for t in TOOLS if t["name"] == tool_name), None)
    if not tool_def:
        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}
    return _execute_tool(tool_name, arguments)


MCP_METHODS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
}


def _make_jsonrpc_response(id_val, result):
    return {"jsonrpc": "2.0", "id": id_val, "result": result}


def _make_jsonrpc_error(id_val, code: int, message: str):
    return {"jsonrpc": "2.0", "id": id_val, "error": {"code": code, "message": message}}


def _process_single_request(request: dict) -> dict:
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    # Notifications (no id) — acknowledge silently
    if req_id is None and method in ("notifications/initialized", "notifications/cancelled"):
        return _make_jsonrpc_response(None, {})

    if method not in MCP_METHODS:
        return _make_jsonrpc_error(req_id, -32601, f"Method not found: {method}")

    try:
        result = MCP_METHODS[method](params)
        return _make_jsonrpc_response(req_id, result)
    except Exception as e:
        logger.exception(f"Error handling method {method}")
        return _make_jsonrpc_error(req_id, -32603, f"Internal error: {str(e)}")


def handler(event, context):
    """AWS Lambda handler for MCP Streamable HTTP transport via API Gateway."""
    try:
        body = json.loads(event.get("body", "{}"))
    except (json.JSONDecodeError, TypeError):
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(_make_jsonrpc_error(None, -32700, "Parse error")),
        }

    if isinstance(body, list):
        responses = [_process_single_request(req) for req in body]
        response_body = json.dumps(responses)
    else:
        response_body = json.dumps(_process_single_request(body))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": response_body,
    }
