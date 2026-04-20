import os
from dataclasses import dataclass

@dataclass
class GitHubConfig:
    """Configuration for GitHub integration."""
    token: str
    api_base_url: str = "https://api.github.com"
    timeout: int = 30
    max_retries: int = 3
    
    def __post_init__(self):
        """Validate GitHub configuration."""
        if not self.token:
            raise ValueError("GitHub token is required")
        if not isinstance(self.token, str):
            raise TypeError("GitHub token must be a string")
                
        if not (len(self.token) == 40 or self.token.startswith(('ghp_', 'ghs_', 'gho_', 'ghu_'))): 
            raise ValueError("Invalid GitHub token format")

@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
    log_file_path: str = "code_reviewer.log"
    max_log_size: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 3

@dataclass
class Config:
    """Main configuration class that combines all configuration sections."""
    github: GitHubConfig
    logging: LoggingConfig
    
    @classmethod
    def from_environment(cls) -> 'Config':
        """Create configuration from environment variables."""
        github_token = os.environ.get("GITHUB_TOKEN", "")
        
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        
        # GitHub configuration
        github_config = GitHubConfig(
            token=github_token,
            timeout=int(os.environ.get("GITHUB_TIMEOUT", "30")),
            max_retries=int(os.environ.get("GITHUB_MAX_RETRIES", "3"))
        )

        # Logging configuration
        log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
        if log_level_str not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid LOG_LEVEL: {log_level_str}. Must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.")
        
        logging_config = LoggingConfig(
            level=log_level_str
        )

        return cls(
            github = github_config,
            logging = logging_config
        )