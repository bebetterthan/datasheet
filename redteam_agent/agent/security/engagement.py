"""
Engagement Loader Module
========================
Loads and validates engagement configurations for security assessments.
"""

import re
import ipaddress
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, date
from fnmatch import fnmatch
from urllib.parse import urlparse
import yaml

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EngagementScope:
    """Represents the scope of an engagement."""
    
    domains: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    include_urls: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    exclude_ip_ranges: List[str] = field(default_factory=list)
    exclude_urls: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if domain is in scope."""
        domain = domain.lower().strip()
        
        # Check exclusions first
        for excl in self.exclude_domains:
            if self._match_domain(domain, excl):
                return False
        
        # Check inclusions
        for incl in self.domains:
            if self._match_domain(domain, incl):
                return True
        
        return False
    
    def is_ip_in_scope(self, ip: str) -> bool:
        """Check if IP is in scope."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check exclusions
            for excl in self.exclude_ip_ranges:
                try:
                    if ip_addr in ipaddress.ip_network(excl, strict=False):
                        return False
                except ValueError:
                    if ip == excl:
                        return False
            
            # Check inclusions
            for incl in self.ip_ranges:
                try:
                    if ip_addr in ipaddress.ip_network(incl, strict=False):
                        return True
                except ValueError:
                    if ip == incl:
                        return True
            
            return False
        except ValueError:
            return False
    
    def is_url_in_scope(self, url: str) -> bool:
        """Check if URL is in scope."""
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        path = parsed.path or '/'
        
        # Check excluded URLs
        for excl in self.exclude_urls:
            if self._match_url(url, excl):
                return False
        
        # Check excluded paths
        for excl_path in self.exclude_paths:
            if self._match_path(path, excl_path):
                return False
        
        # Check included URLs
        for incl in self.include_urls:
            if self._match_url(url, incl):
                return True
        
        # Fall back to domain check
        return self.is_domain_in_scope(domain)
    
    def _match_domain(self, domain: str, pattern: str) -> bool:
        """Match domain against pattern (supports wildcards)."""
        pattern = pattern.lower().strip()
        
        # Wildcard matching
        if pattern.startswith('*.'):
            base = pattern[2:]
            return domain == base or domain.endswith('.' + base)
        
        return fnmatch(domain, pattern)
    
    def _match_url(self, url: str, pattern: str) -> bool:
        """Match URL against pattern."""
        # Handle wildcard at end
        if pattern.endswith('*'):
            return url.startswith(pattern[:-1])
        
        return fnmatch(url, pattern)
    
    def _match_path(self, path: str, pattern: str) -> bool:
        """Match path against pattern."""
        if pattern.endswith('*'):
            return path.startswith(pattern[:-1])
        
        return fnmatch(path, pattern)


@dataclass
class AllowedActions:
    """Represents allowed actions for an engagement."""
    
    recon: Dict[str, Any] = field(default_factory=dict)
    scan: Dict[str, Any] = field(default_factory=dict)
    analyze: Dict[str, Any] = field(default_factory=dict)
    exploit: Dict[str, Any] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)
    
    def is_action_allowed(self, category: str, action: str) -> bool:
        """Check if specific action is allowed."""
        category_config = getattr(self, category, None)
        
        if not category_config:
            return False
        
        if not category_config.get('enabled', False):
            return False
        
        allowed = category_config.get('actions', [])
        return action in allowed or '*' in allowed
    
    def requires_approval(self, category: str) -> bool:
        """Check if category requires approval."""
        category_config = getattr(self, category, None)
        if category_config:
            return category_config.get('requires_approval', False)
        return True
    
    def get_limits(self, category: str) -> Dict[str, Any]:
        """Get rate limits for category."""
        category_config = getattr(self, category, None)
        if category_config:
            return category_config.get('limits', {})
        return {}


@dataclass
class RulesOfEngagement:
    """Rules and constraints for the engagement."""
    
    general_rules: List[str] = field(default_factory=list)
    testing_hours_enabled: bool = False
    testing_hours: Dict[str, Any] = field(default_factory=dict)
    rate_limits: Dict[str, int] = field(default_factory=dict)
    notifications: Dict[str, Any] = field(default_factory=dict)
    
    def is_within_testing_hours(self) -> bool:
        """Check if current time is within allowed testing hours."""
        if not self.testing_hours_enabled:
            return True
        
        now = datetime.now()
        
        # Check day
        allowed_days = self.testing_hours.get('allowed_days', [])
        if allowed_days and now.strftime('%A') not in allowed_days:
            return False
        
        # Check hours
        start_str = self.testing_hours.get('allowed_hours', {}).get('start', '00:00')
        end_str = self.testing_hours.get('allowed_hours', {}).get('end', '23:59')
        
        start_time = datetime.strptime(start_str, '%H:%M').time()
        end_time = datetime.strptime(end_str, '%H:%M').time()
        current_time = now.time()
        
        return start_time <= current_time <= end_time


@dataclass
class Engagement:
    """Complete engagement configuration."""
    
    id: str
    client_name: str
    client_contact: str
    start_date: date
    end_date: date
    assessment_type: str
    scope: EngagementScope
    allowed_actions: AllowedActions
    rules: RulesOfEngagement
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_active(self) -> bool:
        """Check if engagement is currently active."""
        today = date.today()
        return self.start_date <= today <= self.end_date
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        """
        Validate if target is in scope.
        
        Returns:
            Dict with 'allowed' boolean and 'reason' string
        """
        # Check engagement active
        if not self.is_active():
            return {
                'allowed': False,
                'reason': f"Engagement not active. Valid: {self.start_date} to {self.end_date}"
            }
        
        # Check testing hours
        if not self.rules.is_within_testing_hours():
            return {
                'allowed': False,
                'reason': "Outside allowed testing hours"
            }
        
        # Parse target
        if target.startswith(('http://', 'https://')):
            # URL
            if self.scope.is_url_in_scope(target):
                return {'allowed': True, 'reason': "URL in scope"}
            return {'allowed': False, 'reason': "URL not in scope"}
        
        # Check if IP
        try:
            ipaddress.ip_address(target)
            if self.scope.is_ip_in_scope(target):
                return {'allowed': True, 'reason': "IP in scope"}
            return {'allowed': False, 'reason': "IP not in scope"}
        except ValueError:
            pass
        
        # Treat as domain
        if self.scope.is_domain_in_scope(target):
            return {'allowed': True, 'reason': "Domain in scope"}
        
        return {'allowed': False, 'reason': "Target not in scope"}
    
    def validate_action(self, category: str, action: str) -> Dict[str, Any]:
        """
        Validate if action is allowed.
        
        Returns:
            Dict with 'allowed', 'requires_approval', and 'reason'
        """
        if not self.allowed_actions.is_action_allowed(category, action):
            return {
                'allowed': False,
                'requires_approval': False,
                'reason': f"Action '{action}' not allowed in category '{category}'"
            }
        
        requires_approval = self.allowed_actions.requires_approval(category)
        
        return {
            'allowed': True,
            'requires_approval': requires_approval,
            'reason': "Action allowed" + (" (requires approval)" if requires_approval else "")
        }


class EngagementLoader:
    """Loads and manages engagement configurations."""
    
    def __init__(self, engagements_dir: Optional[str] = None):
        """Initialize engagement loader."""
        self.engagements_dir = Path(engagements_dir) if engagements_dir else None
        self.engagements: Dict[str, Engagement] = {}
        self.active_engagement: Optional[Engagement] = None
    
    def load_engagement(self, filepath: Union[str, Path]) -> Engagement:
        """Load engagement from YAML file."""
        path = Path(filepath)
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        engagement = self._parse_engagement(data)
        self.engagements[engagement.id] = engagement
        
        logger.info(f"Loaded engagement: {engagement.id}")
        return engagement
    
    def _parse_engagement(self, data: Dict[str, Any]) -> Engagement:
        """Parse engagement data from YAML."""
        eng_data = data.get('engagement', {})
        scope_data = data.get('scope', {})
        actions_data = data.get('allowed_actions', {})
        rules_data = data.get('rules', {})
        
        # Parse dates
        dates = eng_data.get('dates', {})
        start_date = self._parse_date(dates.get('start'))
        end_date = self._parse_date(dates.get('end'))
        
        # Parse scope
        scope = EngagementScope(
            domains=scope_data.get('domains', []),
            ip_ranges=scope_data.get('ip_ranges', []),
            include_urls=scope_data.get('include_urls', []),
            exclude_domains=scope_data.get('exclude', {}).get('domains', []),
            exclude_ip_ranges=scope_data.get('exclude', {}).get('ip_ranges', []),
            exclude_urls=scope_data.get('exclude', {}).get('urls', []),
            exclude_paths=scope_data.get('exclude', {}).get('paths', [])
        )
        
        # Parse allowed actions
        allowed_actions = AllowedActions(
            recon=actions_data.get('recon', {}),
            scan=actions_data.get('scan', {}),
            analyze=actions_data.get('analyze', {}),
            exploit=actions_data.get('exploit', {}),
            report=actions_data.get('report', {})
        )
        
        # Parse rules
        testing_hours = rules_data.get('testing_hours', {})
        rules = RulesOfEngagement(
            general_rules=rules_data.get('general', []),
            testing_hours_enabled=testing_hours.get('enabled', False),
            testing_hours=testing_hours,
            rate_limits=rules_data.get('rate_limits', {}),
            notifications=rules_data.get('notifications', {})
        )
        
        return Engagement(
            id=eng_data.get('id', 'unknown'),
            client_name=eng_data.get('client', {}).get('name', 'Unknown'),
            client_contact=eng_data.get('client', {}).get('contact', ''),
            start_date=start_date,
            end_date=end_date,
            assessment_type=eng_data.get('type', 'general'),
            scope=scope,
            allowed_actions=allowed_actions,
            rules=rules,
            metadata=data.get('metadata', {})
        )
    
    def _parse_date(self, date_str: Optional[str]) -> date:
        """Parse date string."""
        if not date_str:
            return date.today()
        
        if isinstance(date_str, date):
            return date_str
        
        # Try multiple formats
        formats = ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y']
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).date()
            except ValueError:
                continue
        
        logger.warning(f"Could not parse date: {date_str}, using today")
        return date.today()
    
    def set_active(self, engagement_id: str) -> bool:
        """Set active engagement by ID."""
        if engagement_id in self.engagements:
            self.active_engagement = self.engagements[engagement_id]
            return True
        return False
    
    def get_active(self) -> Optional[Engagement]:
        """Get currently active engagement."""
        return self.active_engagement
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        """Validate target against active engagement."""
        if not self.active_engagement:
            return {
                'allowed': False,
                'reason': "No active engagement configured"
            }
        
        return self.active_engagement.validate_target(target)
    
    def validate_action(self, category: str, action: str) -> Dict[str, Any]:
        """Validate action against active engagement."""
        if not self.active_engagement:
            return {
                'allowed': False,
                'requires_approval': False,
                'reason': "No active engagement configured"
            }
        
        return self.active_engagement.validate_action(category, action)
