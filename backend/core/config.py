"""
Configuration management for the log analyzer tool
"""
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import structlog

logger = structlog.get_logger()


class Settings(BaseSettings):
    """Application settings"""
    
    # App settings
    app_name: str = Field(default="Log Analyzer Tool", alias="app.name")
    app_version: str = Field(default="1.0.0", alias="app.version")
    app_debug: bool = Field(default=False, alias="app.debug")
    
    # Server settings
    server_host: str = Field(default="0.0.0.0", alias="server.host")
    server_port: int = Field(default=8000, alias="server.port")
    
    # Database settings
    database_path: str = Field(default="data/duckdb/logs.db", alias="database.path")
    
    # Auth settings
    auth_secret_key: str = Field(default="change-me-in-production", alias="auth.secret_key")
    auth_algorithm: str = Field(default="HS256", alias="auth.algorithm")
    auth_token_expire_minutes: int = Field(default=30, alias="auth.token_expire_minutes")
    
    # Analysis settings (loaded from YAML)
    analysis_interval: int = 60  # seconds
    analysis_batch_size: int = 10000
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


class ConfigManager:
    """
    Manages configuration from YAML files and environment variables
    """
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        self.config_data: Dict[str, Any] = {}
        self.settings = Settings()
        
        # Load YAML configuration
        if self.config_path.exists():
            self._load_yaml_config()
        else:
            logger.warning("Config file not found", path=str(self.config_path))
    
    def _load_yaml_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                self.config_data = yaml.safe_load(f) or {}
            
            logger.info("Configuration loaded", path=str(self.config_path))
            
        except Exception as e:
            logger.error("Error loading configuration", error=str(e))
            raise
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key (supports dot notation)
        
        Args:
            key: Configuration key (e.g., 'database.path')
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value
    
    def get_database_path(self) -> str:
        """Get database path"""
        return self.get('database.path', self.settings.database_path)
    
    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration"""
        return {
            'host': self.get('server.host', self.settings.server_host),
            'port': self.get('server.port', self.settings.server_port)
        }
    
    def get_auth_config(self) -> Dict[str, Any]:
        """Get authentication configuration"""
        return {
            'secret_key': self.get('auth.secret_key', self.settings.auth_secret_key),
            'algorithm': self.get('auth.algorithm', self.settings.auth_algorithm),
            'token_expire_minutes': self.get('auth.token_expire_minutes', self.settings.auth_token_expire_minutes)
        }
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis configuration"""
        return self.get('analysis', {})
    
    def reload(self):
        """Reload configuration from file"""
        self._load_yaml_config()
        logger.info("Configuration reloaded")


# Global configuration instance
config = ConfigManager()
