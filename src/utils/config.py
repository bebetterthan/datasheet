"""
Configuration management module using Pydantic for validation.
Handles loading configuration from YAML files and environment variables.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class OutputFormat(str, Enum):
    """Supported output formats for the dataset."""
    ALPACA = "alpaca"
    SHAREGPT = "sharegpt"
    JSONL = "jsonl"


class DifficultyLevel(str, Enum):
    """Difficulty levels for security content."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class ScrapingConfig(BaseModel):
    """Configuration for scraping behavior."""
    concurrent_requests: int = Field(default=10, ge=1, le=50)
    delay_between_requests: float = Field(default=1.0, ge=0.1)
    timeout: int = Field(default=30, ge=5, le=120)
    max_retries: int = Field(default=3, ge=1, le=10)
    respect_robots_txt: bool = Field(default=True)
    user_agent: str = Field(
        default="SecurityDatasetBot/1.0 (Research Purpose; Contact: security-dataset@example.com)"
    )
    use_playwright: bool = Field(default=False)
    headless: bool = Field(default=True)


class SourceConfig(BaseModel):
    """Configuration for a single data source."""
    enabled: bool = Field(default=True)
    base_url: str
    max_pages: Optional[int] = Field(default=None)
    categories: Optional[List[str]] = Field(default=None)
    year_range: Optional[List[int]] = Field(default=None)
    extra_params: Optional[Dict[str, Any]] = Field(default=None)

    @field_validator('year_range')
    @classmethod
    def validate_year_range(cls, v):
        if v is not None:
            if len(v) != 2:
                raise ValueError("year_range must have exactly 2 elements [start, end]")
            if v[0] > v[1]:
                raise ValueError("year_range start must be less than or equal to end")
        return v


class HackTricksConfig(SourceConfig):
    """Specific configuration for HackTricks scraper."""
    base_url: str = "https://book.hacktricks.xyz"
    categories: List[str] = Field(default=[
        "pentesting-web",
        "linux-hardening",
        "windows-hardening",
        "network-services-pentesting",
        "mobile-pentesting",
        "cloud-security",
        "forensics",
        "crypto-and-stego"
    ])


class CTFTimeConfig(SourceConfig):
    """Specific configuration for CTFTime scraper."""
    base_url: str = "https://ctftime.org"
    year_range: List[int] = Field(default=[2020, 2024])
    include_writeup_urls: bool = Field(default=True)


class ExploitDBConfig(SourceConfig):
    """Specific configuration for Exploit-DB scraper."""
    base_url: str = "https://www.exploit-db.com"
    verified_only: bool = Field(default=False)
    types: List[str] = Field(default=["webapps", "remote", "local", "dos"])
    years_back: int = Field(default=3)


class CVEConfig(SourceConfig):
    """Specific configuration for CVE scraper."""
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    min_cvss: float = Field(default=7.0, ge=0.0, le=10.0)
    include_poc: bool = Field(default=True)


class NucleiConfig(SourceConfig):
    """Specific configuration for Nuclei Templates scraper."""
    base_url: str = "https://api.github.com/repos/projectdiscovery/nuclei-templates"
    severity_filter: List[str] = Field(default=["critical", "high", "medium"])


class PayloadsConfig(SourceConfig):
    """Specific configuration for PayloadsAllTheThings scraper."""
    base_url: str = "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings"
    include_all_files: bool = Field(default=True)


class OWASPConfig(SourceConfig):
    """Specific configuration for OWASP scraper."""
    base_url: str = "https://owasp.org"
    sources: List[str] = Field(default=[
        "testing-guide",
        "cheatsheets",
        "top-10"
    ])


class SourcesConfig(BaseModel):
    """Configuration for all data sources."""
    hacktricks: HackTricksConfig = Field(default_factory=HackTricksConfig)
    ctftime: CTFTimeConfig = Field(default_factory=CTFTimeConfig)
    exploit_db: ExploitDBConfig = Field(default_factory=ExploitDBConfig)
    cve: CVEConfig = Field(default_factory=CVEConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    payloads: PayloadsConfig = Field(default_factory=PayloadsConfig)
    owasp: OWASPConfig = Field(default_factory=OWASPConfig)


class ProcessingConfig(BaseModel):
    """Configuration for data processing."""
    min_output_length: int = Field(default=100, ge=10)
    max_output_length: int = Field(default=4000, ge=100)
    remove_duplicates: bool = Field(default=True)
    similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    preserve_code_blocks: bool = Field(default=True)
    clean_html: bool = Field(default=True)
    normalize_whitespace: bool = Field(default=True)


class SplitRatioConfig(BaseModel):
    """Configuration for train/validation split."""
    train: float = Field(default=0.9, ge=0.5, le=0.99)
    validation: float = Field(default=0.1, ge=0.01, le=0.5)

    @field_validator('validation')
    @classmethod
    def validate_split_ratio(cls, v, info):
        train = info.data.get('train', 0.9)
        if abs(train + v - 1.0) > 0.001:
            raise ValueError("train + validation must equal 1.0")
        return v


class OutputConfig(BaseModel):
    """Configuration for output generation."""
    format: OutputFormat = Field(default=OutputFormat.ALPACA)
    split_ratio: SplitRatioConfig = Field(default_factory=SplitRatioConfig)
    output_dir: str = Field(default="data/final")
    include_metadata: bool = Field(default=True)
    pretty_print: bool = Field(default=True)
    max_samples_per_file: int = Field(default=10000)


class LLMConfig(BaseModel):
    """Configuration for LLM-based generation (optional)."""
    enabled: bool = Field(default=False)
    provider: str = Field(default="openai")
    model: str = Field(default="gpt-4o-mini")
    api_key: Optional[str] = Field(default=None)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2000, ge=100)


class DatabaseConfig(BaseModel):
    """Configuration for progress tracking database."""
    type: str = Field(default="sqlite")
    path: str = Field(default="data/progress.db")
    redis_url: Optional[str] = Field(default=None)


class ProxyConfig(BaseModel):
    """Configuration for proxy usage."""
    enabled: bool = Field(default=False)
    rotation_enabled: bool = Field(default=False)
    proxies: List[str] = Field(default=[])
    proxy_file: Optional[str] = Field(default=None)


class Config(BaseSettings):
    """Main configuration class that combines all config sections."""
    
    scraping: ScrapingConfig = Field(default_factory=ScrapingConfig)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    
    # Environment variables
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    github_token: Optional[str] = Field(default=None, alias="GITHUB_TOKEN")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

    @classmethod
    def from_yaml(cls, yaml_path: Union[str, Path]) -> "Config":
        """Load configuration from a YAML file."""
        yaml_path = Path(yaml_path)
        if not yaml_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {yaml_path}")
        
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config_dict = yaml.safe_load(f)
        
        return cls(**config_dict)

    @classmethod
    def get_default_config_path(cls) -> Path:
        """Get the default configuration file path."""
        return Path(__file__).parent.parent.parent / "config" / "sources.yaml"

    def to_yaml(self, yaml_path: Union[str, Path]) -> None:
        """Save configuration to a YAML file."""
        yaml_path = Path(yaml_path)
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, indent=2)

    def get_enabled_sources(self) -> Dict[str, SourceConfig]:
        """Get all enabled data sources."""
        sources = {}
        for source_name in ['hacktricks', 'ctftime', 'exploit_db', 'cve', 'nuclei', 'payloads', 'owasp']:
            source_config = getattr(self.sources, source_name, None)
            if source_config and source_config.enabled:
                sources[source_name] = source_config
        return sources

    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for a specific provider."""
        if provider.lower() == "openai":
            return self.openai_api_key or self.llm.api_key
        elif provider.lower() == "anthropic":
            return self.anthropic_api_key
        elif provider.lower() == "github":
            return self.github_token
        return None


def load_config(config_path: Optional[Union[str, Path]] = None) -> Config:
    """
    Load configuration from file or return default configuration.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Config object with all settings
    """
    if config_path:
        return Config.from_yaml(config_path)
    
    default_path = Config.get_default_config_path()
    if default_path.exists():
        return Config.from_yaml(default_path)
    
    return Config()


def save_config(config: Config, config_path: Union[str, Path]) -> None:
    """
    Save configuration to a YAML file.
    
    Args:
        config: Config object to save
        config_path: Path to save configuration to
    """
    config.to_yaml(config_path)


# Default categories mapping for security content
SECURITY_CATEGORIES = {
    "recon": ["reconnaissance", "enumeration", "scanning", "osint", "footprinting"],
    "exploitation": ["exploit", "rce", "injection", "sqli", "xss", "xxe", "ssrf", "deserialization"],
    "privilege_escalation": ["privesc", "privilege escalation", "lateral movement", "sudo", "suid"],
    "persistence": ["persistence", "backdoor", "implant", "rootkit"],
    "credential_access": ["credential", "password", "hash", "kerberos", "mimikatz"],
    "defense_evasion": ["evasion", "bypass", "obfuscation", "antivirus", "edr"],
    "lateral_movement": ["lateral", "pivoting", "port forwarding", "tunneling"],
    "exfiltration": ["exfiltration", "data theft", "c2", "command and control"],
    "web_security": ["web", "http", "api", "owasp", "burp"],
    "network_security": ["network", "tcp", "udp", "firewall", "ids", "ips"],
    "cloud_security": ["aws", "azure", "gcp", "cloud", "kubernetes", "docker"],
    "mobile_security": ["android", "ios", "mobile", "apk"],
    "wireless_security": ["wifi", "wireless", "bluetooth", "wpa", "wep"],
    "cryptography": ["crypto", "encryption", "hash", "rsa", "aes"],
    "forensics": ["forensics", "memory", "disk", "incident response", "malware analysis"],
    "social_engineering": ["phishing", "social engineering", "pretexting", "vishing"],
}
