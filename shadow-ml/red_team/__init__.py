"""
Shadow NDR — Red-Team Validation Harness

Adversary-emulation suite for testing your own Shadow NDR deployment.
This is NOT a generic attack tool: every technique is scoped by
red_team.safety to a localhost/docker-only target allowlist.

Usage (pre-pentest validation):
    python -m red_team.adversary --all --score
    python -m red_team.adversary --campaign auth --verbose
    python -m red_team.adversary --campaign adsb --stealth --duration 300
"""

__version__ = "1.0.0"
