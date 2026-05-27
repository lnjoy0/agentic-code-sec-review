import os
from dataclasses import dataclass
from pydantic import BaseModel, Field, HttpUrl, ValidationError
import logging


logger = logging.getLogger(__name__)


@dataclass
class GitHubConfig:
    """Configuration for GitHub integration."""
    token: str
    event_path: str
    api_base_url: str = "https://api.github.com"
    timeout: int = 30
    max_retries: int = 3


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
    log_file_path: str = "code_reviewer.log"
    max_log_size: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 3


@dataclass
class ScannerConfig:
    """配置扫描器参数"""
    base_sha: str
    head_sha: str
    workspace_dir: str = '.'


class RoleParams(BaseModel):
    """定义每个角色的温度和top_p参数范围"""
    temperature: float = Field(ge=0, le=2.0)
    top_p: float = Field(ge=0, le=1.0)


class LLMConfig(BaseModel):
    """配置LLM参数"""
    model_name: str = 'Qwen3-Coder-30B-A3B-Instruct'
    base_url: HttpUrl = 'http://i-2.gpushare.com:31263/v1'
    api_key: str = 'token-is-not-needed'

    Role: dict[str, RoleParams] = Field(default={
        'Scanner': RoleParams(temperature=0.33, top_p=0.81),
        'Router': RoleParams(temperature=0.1, top_p=0.36),
        'Injection_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Data_Asset_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Infra_Supply_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Logic_Identity_Expert': RoleParams(temperature=0.2, top_p=0.7),
        'General_Expert': RoleParams(temperature=0.4, top_p=0.87),
    })


class AgentConfig(BaseModel):
    """配置Agent参数"""
    max_turns: int = Field(default=20, ge=0) # Agent的最大行动轮数


class ContextConfig(BaseModel):
    """配置代码检索参数"""
    context_max_lines: int = Field(default=200, ge=1) # 最大上下文行数


@dataclass
class Config:
    """Main configuration class that combines all configuration sections."""
    github: GitHubConfig
    logging: LoggingConfig
    scanner: ScannerConfig
    llm: LLMConfig
    agent: AgentConfig
    context: ContextConfig

    @classmethod
    def from_environment(cls) -> 'Config':
        """Create configuration from environment variables."""
        github_token = os.environ.get("GITHUB_TOKEN", "")
        
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        
        # GitHub configuration
        github_config = GitHubConfig(
            token=github_token,
            event_path=os.environ["GITHUB_EVENT_PATH"],
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

        # Scanner configuration
        scanner_config = ScannerConfig(
            base_sha=os.environ.get("BASE_SHA"),
            head_sha=os.environ.get("HEAD_SHA"),
            workspace_dir = os.environ.get("GITHUB_WORKSPACE", ".")
        )

        try:
            # LLM configuration
            llm_config = LLMConfig(
                model_name=os.environ.get("LLM_MODEL_NAME", "Qwen3-Coder-30B-A3B-Instruct"),
                base_url=os.environ.get("LLM_BASE_URL", "http://i-2.gpushare.com:31263/v1"),
                api_key=os.environ.get("LLM_API_KEY", "token-is-not-needed"),

                Role={
                    'Scanner': RoleParams(
                        temperature=os.environ.get("ROLE_SCANNER_TEMP", "0.33"), 
                        top_p=os.environ.get("ROLE_SCANNER_TOP_P", "0.81")),
                    'Router': RoleParams(
                        temperature=os.environ.get("ROLE_ROUTER_TEMP", "0.1"), 
                        top_p=os.environ.get("ROLE_ROUTER_TOP_P", "0.36")),
                    'Injection_Expert': RoleParams(
                        temperature=os.environ.get("ROLE_INJECTION_TEMP", "0.14"), 
                        top_p=os.environ.get("ROLE_INJECTION_TOP_P", "0.62")),
                    'Data_Asset_Expert': RoleParams(
                        temperature=os.environ.get("ROLE_DATA_ASSET_TEMP", "0.14"), 
                        top_p=os.environ.get("ROLE_DATA_ASSET_TOP_P", "0.62")),
                    'Infra_Supply_Expert': RoleParams(
                        temperature=os.environ.get("ROLE_INFRA_SUPPLY_TEMP", "0.14"), 
                        top_p=os.environ.get("ROLE_INFRA_SUPPLY_TOP_P", "0.62")),
                    'Logic_Identity_Expert': RoleParams(
                        temperature=os.environ.get("ROLE_LOGIC_IDENTITY_TEMP", "0.2"), 
                        top_p=os.environ.get("ROLE_LOGIC_IDENTITY_TOP_P", "0.7")),
                    'General_Expert': RoleParams(
                        temperature=os.environ.get("ROLE_GENERAL_TEMP", "0.4"), 
                        top_p=os.environ.get("ROLE_GENERAL_TOP_P", "0.87")),
                }
            )

            # Agent configuration
            agent_config = AgentConfig(
                max_turns=os.environ.get("AGENT_MAX_TURNS", "20")
            )

            # Code retriever configuration
            context_config = ContextConfig(
                context_max_lines=os.environ.get("CONTEXT_MAX_LINES", "200")
            )
        except ValidationError as e:
            logger.error(f"参数错误：{e}")
            raise

        return cls(
            github = github_config,
            logging = logging_config,
            scanner = scanner_config,
            agent = agent_config,
            llm = llm_config,
            context = context_config
        )