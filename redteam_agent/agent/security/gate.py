"""
Security Gate Module (Gate Zero)
================================

Authorization and scope validation for all agent actions.
CRITICAL: This module prevents unauthorized actions.
"""

from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
from enum import Enum

from agent.utils.logger import get_logger
from agent.utils.config import Config


class AuthorizationStatus(Enum):
    """Authorization decision status."""
    AUTHORIZED = "authorized"
    DENIED = "denied"
    PENDING = "pending"
    REQUIRES_CONFIRMATION = "requires_confirmation"


@dataclass
class AuthorizationResult:
    """Result of authorization check."""
    status: AuthorizationStatus
    authorized: bool
    reason: str
    warnings: List[str]
    restrictions: List[str]
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "authorized": self.authorized,
            "reason": self.reason,
            "warnings": self.warnings,
            "restrictions": self.restrictions,
            "timestamp": self.timestamp
        }


class SecurityGate:
    """
    Security Gate (Gate Zero) for the Red Team Agent.
    
    CRITICAL COMPONENT: All actions must pass through this gate.
    
    Responsibilities:
        - Validate targets against whitelist/blacklist
        - Prevent actions on unauthorized systems
        - Log all authorization decisions
        - Enforce scope boundaries
        
    Usage:
        gate = SecurityGate(whitelist=["10.0.0.0/24"])
        result = gate.authorize(action="scan", target="10.0.0.5")
        if result.authorized:
            # Proceed with action
    """
    
    # Actions that are always safe (don't need target validation)
    SAFE_ACTIONS = {"analyze", "parse", "report", "summarize", "think", "plan"}
    
    # Actions that require strict validation
    SENSITIVE_ACTIONS = {"exploit", "inject", "modify", "delete", "backdoor"}
    
    # Default internal networks (usually should be blocked)
    DEFAULT_BLACKLIST = [
        "127.0.0.0/8",      # Localhost
        "169.254.0.0/16",   # Link-local
        "224.0.0.0/4",      # Multicast
        "255.255.255.255/32"  # Broadcast
    ]
    
    def __init__(
        self,
        config: Optional[Config] = None,
        whitelist: Optional[List[str]] = None,
        blacklist: Optional[List[str]] = None,
        enabled: bool = True,
        require_confirmation: bool = True
    ):
        """
        Initialize Security Gate.
        
        Args:
            config: Configuration object
            whitelist: List of allowed targets (IPs, CIDRs, domains)
            blacklist: List of blocked targets
            enabled: Whether security checks are enabled
            require_confirmation: Require confirmation for sensitive actions
        """
        self.logger = get_logger("SecurityGate")
        self.config = config or Config()
        
        # Security settings
        self.enabled = enabled
        self.require_confirmation = require_confirmation
        
        # Initialize lists
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._whitelist_networks: List[ipaddress.IPv4Network] = []
        self._blacklist_networks: List[ipaddress.IPv4Network] = []
        
        # Load from config if not provided
        if whitelist is None:
            whitelist = self.config.get("security.whitelist", [])
        if blacklist is None:
            blacklist = self.config.get("security.blacklist", [])
            
        # Add default blacklist
        blacklist = list(blacklist) + self.DEFAULT_BLACKLIST
        
        self._parse_whitelist(whitelist)
        self._parse_blacklist(blacklist)
        
        # Authorization log
        self._auth_log: List[Dict[str, Any]] = []
        
        self.logger.info(
            f"SecurityGate initialized. Whitelist: {len(self._whitelist)} entries, "
            f"Blacklist: {len(self._blacklist)} entries"
        )
        
    def _parse_whitelist(self, items: List[str]) -> None:
        """Parse whitelist entries."""
        for item in items:
            item = item.strip()
            if not item:
                continue
                
            try:
                # Try parsing as network
                network = ipaddress.ip_network(item, strict=False)
                self._whitelist_networks.append(network)
                self._whitelist.add(item)
            except ValueError:
                # Treat as domain/hostname
                self._whitelist.add(item.lower())
                
    def _parse_blacklist(self, items: List[str]) -> None:
        """Parse blacklist entries."""
        for item in items:
            item = item.strip()
            if not item:
                continue
                
            try:
                network = ipaddress.ip_network(item, strict=False)
                self._blacklist_networks.append(network)
                self._blacklist.add(item)
            except ValueError:
                self._blacklist.add(item.lower())
                
    def authorize(
        self,
        action: str,
        target: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> AuthorizationResult:
        """
        Check if an action is authorized.
        
        Args:
            action: The action to perform
            target: Target of the action (IP, domain, URL)
            params: Additional parameters
            
        Returns:
            AuthorizationResult with decision
        """
        timestamp = datetime.now().isoformat()
        warnings = []
        restrictions = []
        
        # If security is disabled, allow everything (NOT RECOMMENDED)
        if not self.enabled:
            self.logger.warning("Security gate is DISABLED - allowing all actions")
            return AuthorizationResult(
                status=AuthorizationStatus.AUTHORIZED,
                authorized=True,
                reason="Security gate disabled",
                warnings=["Security gate is disabled - not recommended"],
                restrictions=[],
                timestamp=timestamp
            )
            
        # Safe actions don't need target validation
        if action.lower() in self.SAFE_ACTIONS:
            return AuthorizationResult(
                status=AuthorizationStatus.AUTHORIZED,
                authorized=True,
                reason=f"Action '{action}' is classified as safe",
                warnings=[],
                restrictions=[],
                timestamp=timestamp
            )
            
        # Sensitive actions require extra scrutiny
        if action.lower() in self.SENSITIVE_ACTIONS:
            warnings.append(f"Action '{action}' is classified as sensitive")
            restrictions.append("Requires explicit confirmation")
            
            if self.require_confirmation:
                result = AuthorizationResult(
                    status=AuthorizationStatus.REQUIRES_CONFIRMATION,
                    authorized=False,
                    reason=f"Sensitive action '{action}' requires confirmation",
                    warnings=warnings,
                    restrictions=restrictions,
                    timestamp=timestamp
                )
                self._log_decision(action, target, result)
                return result
                
        # No target specified
        if not target:
            return AuthorizationResult(
                status=AuthorizationStatus.DENIED,
                authorized=False,
                reason="No target specified for action requiring target",
                warnings=warnings,
                restrictions=restrictions,
                timestamp=timestamp
            )
            
        # Normalize target
        normalized_target = self._normalize_target(target)
        
        # Check blacklist first (always deny)
        if self._is_blacklisted(normalized_target):
            result = AuthorizationResult(
                status=AuthorizationStatus.DENIED,
                authorized=False,
                reason=f"Target '{target}' is blacklisted",
                warnings=["Attempted access to blacklisted target"],
                restrictions=["Target is explicitly blocked"],
                timestamp=timestamp
            )
            self._log_decision(action, target, result)
            return result
            
        # Check whitelist
        if self._whitelist or self._whitelist_networks:
            if not self._is_whitelisted(normalized_target):
                result = AuthorizationResult(
                    status=AuthorizationStatus.DENIED,
                    authorized=False,
                    reason=f"Target '{target}' is not in whitelist",
                    warnings=["Target not in authorized scope"],
                    restrictions=["Only whitelisted targets are allowed"],
                    timestamp=timestamp
                )
                self._log_decision(action, target, result)
                return result
        else:
            # No whitelist configured - deny by default
            warnings.append("No whitelist configured - defaulting to deny")
            result = AuthorizationResult(
                status=AuthorizationStatus.DENIED,
                authorized=False,
                reason="No whitelist configured - cannot authorize",
                warnings=warnings,
                restrictions=["Configure whitelist before testing"],
                timestamp=timestamp
            )
            self._log_decision(action, target, result)
            return result
            
        # All checks passed
        result = AuthorizationResult(
            status=AuthorizationStatus.AUTHORIZED,
            authorized=True,
            reason=f"Target '{target}' is in whitelist, action '{action}' is allowed",
            warnings=warnings,
            restrictions=restrictions,
            timestamp=timestamp
        )
        self._log_decision(action, target, result)
        return result
        
    def _normalize_target(self, target: str) -> str:
        """Normalize target for comparison."""
        target = target.strip().lower()
        
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        
        # Remove path
        target = target.split('/')[0]
        
        # Remove port
        target = target.split(':')[0]
        
        return target
        
    def _is_whitelisted(self, target: str) -> bool:
        """Check if target is in whitelist."""
        # Direct domain/hostname match
        if target in self._whitelist:
            return True
            
        # Check wildcard domains
        for entry in self._whitelist:
            if entry.startswith("*."):
                pattern = entry[2:]
                if target.endswith(pattern) or target == pattern:
                    return True
                    
        # Check IP networks
        try:
            ip = ipaddress.ip_address(target)
            for network in self._whitelist_networks:
                if ip in network:
                    return True
        except ValueError:
            pass  # Not an IP address
            
        return False
        
    def _is_blacklisted(self, target: str) -> bool:
        """Check if target is in blacklist."""
        # Direct match
        if target in self._blacklist:
            return True
            
        # Check IP networks
        try:
            ip = ipaddress.ip_address(target)
            for network in self._blacklist_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
            
        # Check for localhost aliases
        localhost_aliases = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
        if target in localhost_aliases:
            return True
            
        return False
        
    def _log_decision(
        self,
        action: str,
        target: Optional[str],
        result: AuthorizationResult
    ) -> None:
        """Log authorization decision."""
        entry = {
            "timestamp": result.timestamp,
            "action": action,
            "target": target,
            "result": result.to_dict()
        }
        
        self._auth_log.append(entry)
        
        if result.authorized:
            self.logger.info(f"AUTHORIZED: {action} on {target}")
        else:
            self.logger.warning(
                f"DENIED: {action} on {target} - {result.reason}"
            )
            
    def add_to_whitelist(self, target: str) -> None:
        """Add target to whitelist."""
        self._parse_whitelist([target])
        self.logger.info(f"Added to whitelist: {target}")
        
    def add_to_blacklist(self, target: str) -> None:
        """Add target to blacklist."""
        self._parse_blacklist([target])
        self.logger.info(f"Added to blacklist: {target}")
        
    def remove_from_whitelist(self, target: str) -> None:
        """Remove target from whitelist."""
        target = target.strip().lower()
        self._whitelist.discard(target)
        self._whitelist_networks = [
            n for n in self._whitelist_networks
            if str(n) != target
        ]
        self.logger.info(f"Removed from whitelist: {target}")
        
    def get_authorization_log(self) -> List[Dict[str, Any]]:
        """Get all authorization decisions."""
        return self._auth_log.copy()
        
    def clear_log(self) -> None:
        """Clear authorization log."""
        self._auth_log.clear()
        
    def get_whitelist(self) -> List[str]:
        """Get current whitelist."""
        return list(self._whitelist)
        
    def get_blacklist(self) -> List[str]:
        """Get current blacklist."""
        return list(self._blacklist)
        
    def validate_scope(
        self,
        targets: List[str]
    ) -> Dict[str, AuthorizationResult]:
        """
        Validate multiple targets for scope.
        
        Args:
            targets: List of targets to validate
            
        Returns:
            Dictionary of target -> AuthorizationResult
        """
        results = {}
        for target in targets:
            results[target] = self.authorize("scope_check", target)
        return results
