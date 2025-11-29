"""CSPM — Cloud security posture from a config export (public buckets, open SGs, weak IAM)."""
from cspm.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
