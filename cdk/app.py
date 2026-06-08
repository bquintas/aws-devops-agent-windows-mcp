#!/usr/bin/env python3
"""CDK App entry point for SSM MCP Server."""

import aws_cdk as cdk

from stack import SsmMcpServerStack

app = cdk.App()

SsmMcpServerStack(
    app,
    "SsmMcpServerStack",
    description="MCP Server for AWS DevOps Agent - Windows Instance Diagnostics via SSM",
)

app.synth()
