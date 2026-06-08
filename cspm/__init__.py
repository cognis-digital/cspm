"""CSPM — Cloud Security Posture Management (defensive triage).

Reads a cloud configuration export (JSON) and reports posture findings:
public storage buckets, open security groups, weak IAM, and more.

Standard library only. Zero install. Analysis on artifacts you own.
"""
from .core import (
    Finding,
    SEVERITY_ORDER,
    load_config,
    scan,
    summarize,
)

TOOL_NAME = "cspm"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "SEVERITY_ORDER",
    "load_config",
    "scan",
    "summarize",
    "TOOL_NAME",
    "TOOL_VERSION",
]
