"""
Config Module
=============

Configuration management for the Red Team Agent.
Supports loading from YAML files, environment variables, and runtime overrides.
"""

from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from dataclasses import dataclass, field
import os
import yaml
import re


@dataclass
class LLMConfig:
    """LLM configuration settings."""
    provider: str = "local"
    model_path: str = ""
    base_model: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    api_url: str = "http://localhost:8000/v1"
    api_key: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 0.9
    timeout: int = 120


@dataclass
class AgentConfig:
    """Agent core configuration."""
    name: str = "RedTeam Agent"
    version: str = "1.0.0"
    max_iterations: int = 20
    task_timeout: int = 600
    step_timeout: int = 120
    verbose: bool = True
    mode: str = "autonomous"
    require_approval: bool = False


@dataclass
class SecurityConfig:
    """Security (Gate Zero) configuration."""
    enabled: bool = True
    require_authorization: bool = True
    engagement_file: str = "./configs/engagement.yaml"
    whitelist_only: bool = True
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)
    log_all_actions: bool = True
    audit_log_path: str = "./logs/audit/"


@dataclass  
class MemoryConfig:
    """Memory configuration."""
    max_context_tokens: int = 8000
    summarize_threshold: int = 6000
    persist_memory: bool = False


@dataclass
class OutputConfig:
    """Output configuration."""
    directory: str = "./outputs"
    auto_report: bool = True
    report_format: str = "json"
    save_raw_outputs: bool = True


class Config:
    """
    Configuration manager for the Red Team Agent.
    
    Handles loading and accessing configuration from multiple sources:
    - Default values
    - YAML config file
    - Environment variables
    """
    
    DEFAULT_CONFIG = {
        # LLM Settings
        "llm": {
            "model_path": "~/redteam-ai-agent/outputs/run_20251130_084846/final_model",
            "base_model": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "max_tokens": 2048,
            "temperature": 0.3,
            "top_p": 0.9
        },
        
        # Agent Settings
        "agent": {
            "max_steps": 50,
            "step_timeout": 300,  # 5 minutes per step
            "total_timeout": 3600,  # 1 hour total
            "require_approval": False,
            "allowed_tools": ["recon", "scanner", "analyzer"]
        },
        
        # Security Settings (Gate Zero)
        "security": {
            "enabled": True,
            "whitelist_only": True,
            "whitelist": [],  # Must be configured
            "blacklist": [
                "127.0.0.1",
                "localhost",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ],
            "require_scope_confirmation": True,
            "log_all_actions": True
        },
        
        # Memory Settings
        "memory": {
            "max_context_tokens": 8000,
            "summarize_threshold": 6000,
            "persist_long_term": False
        },
        
        # Logging Settings
        "logging": {
            "level": "INFO",
            "file": "logs/agent.log",
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        },
        
        # Output Settings
        "output": {
            "directory": "outputs",
            "report_format": "json",
            "save_raw_outputs": True
        },
        
        # Tool Settings
        "tools": {
            "nmap": {
                "enabled": True,
                "default_args": "-sV -sC",
                "timeout": 300
            },
            "gobuster": {
                "enabled": True,
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "timeout": 600
            },
            "nuclei": {
                "enabled": True,
                "templates_path": "~/nuclei-templates",
                "timeout": 600
            },
            "ffuf": {
                "enabled": True,
                "timeout": 600
            }
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Config.
        
        Args:
            config_path: Optional path to YAML config file
        """
        self._config: Dict[str, Any] = {}
        self._load_defaults()
        
        if config_path:
            self._load_file(config_path)
            
        self._load_env_overrides()
        
    def _load_defaults(self) -> None:
        """Load default configuration."""
        self._config = self._deep_copy(self.DEFAULT_CONFIG)
        
    def _load_file(self, path: str) -> None:
        """Load configuration from YAML file."""
        config_path = Path(path).expanduser()
        
        if config_path.exists():
            with open(config_path) as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self._deep_merge(self._config, file_config)
                    
    def _load_env_overrides(self) -> None:
        """Load configuration from environment variables."""
        # LLM settings
        if os.getenv("REDTEAM_MODEL_PATH"):
            self._config["llm"]["model_path"] = os.getenv("REDTEAM_MODEL_PATH")
        if os.getenv("REDTEAM_BASE_MODEL"):
            self._config["llm"]["base_model"] = os.getenv("REDTEAM_BASE_MODEL")
            
        # Agent settings
        if os.getenv("REDTEAM_MAX_STEPS"):
            self._config["agent"]["max_steps"] = int(os.getenv("REDTEAM_MAX_STEPS"))
            
        # Security settings
        if os.getenv("REDTEAM_WHITELIST"):
            self._config["security"]["whitelist"] = os.getenv("REDTEAM_WHITELIST").split(",")
            
        # Logging
        if os.getenv("REDTEAM_LOG_LEVEL"):
            self._config["logging"]["level"] = os.getenv("REDTEAM_LOG_LEVEL")
            
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Key in dot notation (e.g., "llm.model_path")
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key: Key in dot notation
            value: Value to set
        """
        keys = key.split(".")
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.
        
        Args:
            section: Section name (e.g., "llm", "security")
            
        Returns:
            Section configuration dictionary
        """
        return self._config.get(section, {})
        
    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary."""
        return self._deep_copy(self._config)
        
    def save(self, path: str) -> None:
        """
        Save configuration to YAML file.
        
        Args:
            path: Path to save file
        """
        config_path = Path(path).expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, "w") as f:
            yaml.dump(self._config, f, default_flow_style=False)
            
    @staticmethod
    def _deep_copy(obj: Any) -> Any:
        """Create a deep copy of a nested dictionary."""
        if isinstance(obj, dict):
            return {k: Config._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [Config._deep_copy(item) for item in obj]
        else:
            return obj
            
    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> None:
        """Deep merge override into base dictionary."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value
                
    def validate(self) -> List[str]:
        """
        Validate configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required settings
        if not self.get("llm.model_path") and not self.get("llm.api_url"):
            errors.append("Either llm.model_path or llm.api_url is required")
            
        # Check security settings
        if self.get("security.enabled") and self.get("security.whitelist_only"):
            whitelist = self.get("security.whitelist", [])
            engagement_file = self.get("security.engagement_file")
            if not whitelist and not engagement_file:
                errors.append("Security whitelist is empty and no engagement file configured")
                
        # Check output directory
        output_dir = self.get("output.directory")
        if output_dir:
            path = Path(output_dir).expanduser()
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create output directory: {e}")
                
        return errors
    
    def get_llm_config(self) -> LLMConfig:
        """Get LLM configuration as dataclass."""
        llm = self.get_section("llm")
        return LLMConfig(
            provider=llm.get("provider", "local"),
            model_path=llm.get("model_path", ""),
            base_model=llm.get("base_model", ""),
            api_url=llm.get("api_url", ""),
            api_key=llm.get("api_key"),
            max_tokens=llm.get("max_tokens", 4096),
            temperature=llm.get("temperature", 0.7),
            top_p=llm.get("top_p", 0.9),
            timeout=llm.get("timeout", 120)
        )
    
    def get_agent_config(self) -> AgentConfig:
        """Get agent configuration as dataclass."""
        agent = self.get_section("agent")
        return AgentConfig(
            name=agent.get("name", "RedTeam Agent"),
            version=agent.get("version", "1.0.0"),
            max_iterations=agent.get("max_iterations", 20),
            task_timeout=agent.get("task_timeout", 600),
            step_timeout=agent.get("step_timeout", 120),
            verbose=agent.get("verbose", True),
            mode=agent.get("mode", "autonomous"),
            require_approval=agent.get("require_approval", False)
        )
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration as dataclass."""
        sec = self.get_section("security")
        return SecurityConfig(
            enabled=sec.get("enabled", True),
            require_authorization=sec.get("require_authorization", True),
            engagement_file=sec.get("engagement_file", ""),
            whitelist_only=sec.get("whitelist_only", True),
            whitelist=sec.get("whitelist", []),
            blacklist=sec.get("blacklist", []),
            log_all_actions=sec.get("log_all_actions", True),
            audit_log_path=sec.get("audit_log_path", "./logs/audit/")
        )
    
    def get_memory_config(self) -> MemoryConfig:
        """Get memory configuration as dataclass."""
        mem = self.get_section("memory")
        return MemoryConfig(
            max_context_tokens=mem.get("max_context_tokens", 8000),
            summarize_threshold=mem.get("summarize_threshold", 6000),
            persist_memory=mem.get("persist_memory", False)
        )
    
    def get_output_config(self) -> OutputConfig:
        """Get output configuration as dataclass."""
        out = self.get_section("output")
        return OutputConfig(
            directory=out.get("directory", "./outputs"),
            auto_report=out.get("auto_report", True),
            report_format=out.get("report_format", "json"),
            save_raw_outputs=out.get("save_raw_outputs", True)
        )
        
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access."""
        return self.get(key)
        
    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dictionary-style setting."""
        self.set(key, value)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"Config(sections={list(self._config.keys())})"


class ConfigValidator:
    """Validates configuration values."""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format."""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def validate_path(path: str, must_exist: bool = False) -> bool:
        """Validate file path."""
        try:
            p = Path(path).expanduser()
            if must_exist:
                return p.exists()
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_ip_or_cidr(value: str) -> bool:
        """Validate IP address or CIDR notation."""
        import ipaddress
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False


def load_config(path: Optional[str] = None) -> Config:
    """
    Load configuration from file or defaults.
    
    Args:
        path: Optional path to config file
        
    Returns:
        Config instance
    """
    # Try to find config file
    if path is None:
        search_paths = [
            "config.yaml",
            "configs/config.yaml",
            "configs/agent_config.yaml",
            "~/.redteam-agent/config.yaml"
        ]
        
        for search_path in search_paths:
            expanded = Path(search_path).expanduser()
            if expanded.exists():
                path = str(expanded)
                break
                
    return Config(path)


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple configuration dictionaries.
    
    Later configs override earlier ones.
    
    Args:
        *configs: Configuration dictionaries to merge
        
    Returns:
        Merged configuration
    """
    result = {}
    for config in configs:
        Config._deep_merge(result, config)
    return result
