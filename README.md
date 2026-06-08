# SSM-Based MCP Server — Windows Instance Diagnostics

A serverless MCP server that enables AWS DevOps Agent to investigate Windows EC2 instances via SSM RunCommand. General-purpose read-only diagnostics — event logs, services, system info, and arbitrary PowerShell (verb-allowlisted).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  AWS DevOps Agent                                                           │
│                                                                             │
│  "Why is this Windows instance unhealthy?"                                  │
│       │                                                                     │
│       │  MCP tool call (JSON-RPC 2.0 over HTTPS)                            │
│       ▼                                                                     │
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │ SigV4-signed request (assumes ssm-mcp-devops-agent-role)
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  API Gateway (REST API, IAM Auth)                                           │
│  POST /mcp                                                                  │
│  Throttle: 10 req/sec                                                       │
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │ Lambda Proxy Integration
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Lambda: ssm-mcp-server (Python 3.12, 256 MB, 60s timeout)                  │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ MCP Protocol Handler (JSON-RPC 2.0)                                    │ │
│  │  • initialize    → server capabilities                                 │ │
│  │  • tools/list    → tool catalog                                        │ │
│  │  • tools/call    → validate + execute                                  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Security Layer                                                         │ │
│  │  • Instance ID allowlist (from SSM Parameter Store)                    │ │
│  │  • PowerShell verb allowlist (Get-, Test-, Select-, ...)               │ │
│  │  • Blocked pattern detection (no writes, no exfiltration)              │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │ ssm:SendCommand (cross-region capable)
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AWS Systems Manager                                                        │
│  Document: AWS-RunPowerShellScript                                          │
│  Target: EC2 instances tagged AllowMcpAccess=true                           │
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │ SSM Agent (pre-installed on Windows AMIs)
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Windows EC2 Instance (any region)                                          │
│                                                                             │
│  Executes read-only PowerShell → returns stdout/stderr via SSM              │
│  Examples:                                                                  │
│    • Get-WinEvent -LogName Application                                      │
│    • Get-Service | Where-Object Status -eq Stopped                          │
│    • Get-CimInstance Win32_OperatingSystem                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

No SSH, no RDP, no ports opened. Communication goes through SSM service endpoints. Supports cross-region — the Lambda can target instances in any region via an optional `region` parameter on each tool.

## Tools

| Tool | Description |
|------|-------------|
| `run_powershell_command` | Run any read-only PowerShell command (verb-allowlisted: Get-, Test-, Select-, etc.) |
| `get_windows_event_logs` | Query any Windows Event Log with filtering by level, source, time range |
| `get_windows_services` | Check Windows service status (specific services or all) |
| `get_system_info` | OS version, uptime, CPU/memory/disk usage, network config |

### Verb Allowlist

The `run_powershell_command` tool permits these PowerShell verbs:

`Get-`, `Test-`, `Select-`, `Format-`, `Measure-`, `ConvertTo-`, `ConvertFrom-`, `Compare-`, `Find-`, `Resolve-`, `Trace-`, `Debug-`, `Where-`, `Sort-`, `Group-`, `Out-`

All write/destructive verbs (Set-, Remove-, Stop-, Start-, New-, Invoke-) are blocked. Pipeline commands are validated at each segment.

## Prerequisites

- AWS account with CDK bootstrapped (`cdk bootstrap`)
- Target Windows instances with SSM Agent running
- Target instances tagged with `AllowMcpAccess=true`
- Instance IAM profile includes `AmazonSSMManagedInstanceCore`
- [uv](https://docs.astral.sh/uv/) and Node.js installed

## Setup

```bash
uv sync
source .venv/bin/activate
```

## Deploy

```bash
cd cdk
npx cdk deploy
```

Optionally provide instance IDs at deploy time (otherwise update via Parameter Store later):

```bash
npx cdk deploy --parameters AllowedInstanceIds="i-0abc123,i-0def456"
```

Account ID and region are auto-discovered from your AWS credentials.

### Stack Outputs

- **McpEndpointUrl** — Register this in DevOps Agent console
- **InvocationRoleArn** — IAM role ARN for DevOps Agent
- **AllowedInstanceIdsParameterName** — Update the instance allowlist without redeploying

## Update Allowed Instances (No Redeploy)

```bash
aws ssm put-parameter \
  --name "/mcp-server/allowed-instance-ids" \
  --value "i-0abc123,i-0def456,i-0newinstance" \
  --type String \
  --overwrite
```

## Register in DevOps Agent

1. Navigate to **Capability Providers → Register MCP Server**
2. Name: `windows-instance-diagnostics`
3. Endpoint: `<McpEndpointUrl from stack output>`
4. Auth: AWS SigV4
5. Region: your deployment region
6. Service Name: `execute-api`
7. IAM Role: `<InvocationRoleArn from stack output>`

## Security

- **Verb allowlist**: Only read-only PowerShell verbs permitted
- **Blocked patterns**: Write operations, network calls, process management detected and rejected at multiple levels
- **Instance allowlist**: SSM Parameter Store + tag-based IAM condition (defense in depth)
- **Cross-region**: Works across any AWS region from a single deployment
- **IAM auth**: API Gateway uses SigV4 — only the DevOps Agent service principal can invoke
- **No arbitrary execution**: Even `run_powershell_command` validates every pipeline segment
- **Audit**: All invocations logged to CloudWatch with structured JSON (tool, instance, region, duration, status)

## Project Structure

```
├── lambda_code/
│   └── handler.py          # MCP server (JSON-RPC 2.0 + verb validation + SSM)
├── cdk/
│   ├── app.py              # CDK app entry point
│   ├── stack.py            # Infrastructure (API GW, Lambda, IAM, SSM Param)
│   └── cdk.json            # CDK config
├── pyproject.toml          # uv project config
└── README.md
```
