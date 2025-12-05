"""
Security Package
================

Security layer (Gate Zero) for the Red Team Agent.
"""

from agent.security.gate import SecurityGate, AuthorizationResult
from agent.security.engagement import (
    Engagement,
    EngagementLoader,
    EngagementScope,
    AllowedActions,
    RulesOfEngagement
)

__all__ = [
    "SecurityGate",
    "AuthorizationResult",
    "Engagement",
    "EngagementLoader",
    "EngagementScope",
    "AllowedActions",
    "RulesOfEngagement"
]
