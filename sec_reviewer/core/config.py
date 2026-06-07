import os
from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel, Field, ValidationError, ConfigDict, field_validator
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


class ScannerConfig(BaseModel):
    """配置扫描器参数"""
    base_sha: str
    head_sha: str
    workspace_dir: str = '.'
    context_max_lines: int = Field(default=500, ge=1)
    semgrep_rules: str = ' '.join([
                    "--config=p/default", "--config=p/security-audit", "--config=p/secrets", 
                    "--config=p/r2c-security-audit", "--config=p/insecure-transport",
                    "--config=p/python", "--config=p/django", "--config=p/flask", "--config=p/sql-injection", # python相关规则集
                    ])
    semgrep_severity: Literal['ERROR', 'WARNING', 'INFO', 'Critical', 'High', 'Medium', 'Low'] = Field(default='ERROR')
    trivy_severity: str = Field(default='HIGH,CRITICAL')

    @field_validator('trivy_severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}

        input_levels = [item.strip().upper() for item in v.split(',')]
        invalid_levels = [item for item in input_levels if item not in allowed]
        
        if invalid_levels:
            raise ValueError(f"存在无效的严重级别: {invalid_levels}. 允许范围: {allowed}")
        
        return ",".join(sorted(list(set(input_levels))))



class RoleParams(BaseModel):
    """定义每个角色的温度和top_p参数范围"""
    temperature: float = Field(ge=0, le=2.0)
    top_p: float = Field(ge=0, le=1.0)


class LLMConfig(BaseModel):
    """配置LLM参数"""
    model_config = ConfigDict(frozen=True)

    model_name: str
    base_url: str
    api_key: str

    Role: dict[str, RoleParams] = Field(default={
        'Scanner': RoleParams(temperature=0.33, top_p=0.81),
        'Router': RoleParams(temperature=0.1, top_p=0.36),
        'Injection_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Data_Asset_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Infra_Supply_Expert': RoleParams(temperature=0.14, top_p=0.62),
        'Logic_Identity_Expert': RoleParams(temperature=0.2, top_p=0.7),
        'General_Expert': RoleParams(temperature=0.4, top_p=0.87),
        'Critic': RoleParams(temperature=0.12, top_p=0.45)
    })


class AgentConfig(BaseModel):
    """配置Agent参数"""
    agent_max_rounds: int = Field(default=30, ge=0) # Agent的最大行动轮数
    max_critical_rounds: int = Field(default=2, ge=0)


class CodeRetrievalConfig(BaseModel):
    """配置代码检索参数"""
    context_max_lines: int = Field(default=200, ge=1) # 检索代码时的最大上下文行数
    single_line_max_length: int = Field(default=500, ge=1) # 检索代码时的单行最大字符数


@dataclass
class Config:
    """Main configuration class that combines all configuration sections."""
    github: GitHubConfig
    logging: LoggingConfig
    scanner: ScannerConfig
    llm: LLMConfig
    agent: AgentConfig
    retrieval: CodeRetrievalConfig

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
        config_kwargs = {
            "base_sha": os.environ.get("BASE_SHA"),
            "head_sha": os.environ.get("HEAD_SHA"),
        }
        if os.environ.get("GITHUB_WORKSPACE"):
            config_kwargs["workspace_dir"] = os.environ.get("GITHUB_WORKSPACE")
        if os.environ.get("SCAN_CONTEXT_MAX_LINES"):
            config_kwargs["context_max_lines"] = int(os.environ.get("SCAN_CONTEXT_MAX_LINES"))
        if os.environ.get("SEMGREP_RULES"):
            config_kwargs["semgrep_rules"] = os.environ.get("SEMGREP_RULES")
        if os.environ.get("SEMGREP_SEVERITY"):
            config_kwargs["semgrep_severity"] = os.environ.get("SEMGREP_SEVERITY")
        if os.environ.get("TRIVY_SEVERITY"):
            config_kwargs["trivy_severity"] = os.environ.get("TRIVY_SEVERITY")

        scanner_config = ScannerConfig(**config_kwargs)

        try:
            # LLM configuration
            llm_config = LLMConfig(
                model_name=os.environ.get("LLM_MODEL_NAME"),
                base_url=os.environ.get("LLM_BASE_URL"),
                api_key=os.environ.get("LLM_API_KEY"),

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
                    'Critic': RoleParams(
                        temperature=os.environ.get("ROLE_CRITIC_TEMP", "0.12"), 
                        top_p=os.environ.get("ROLE_CRITIC_TOP_P", "0.45")),
                }
            )

            # Agent configuration
            agent_config = AgentConfig(
                agent_max_rounds=os.environ.get("AGENT_MAX_ROUNDS", "30"),
                max_critical_rounds = os.environ.get("MAX_CRITICAL_ROUNDS", "2")
            )

            # Code retriever configuration
            code_retrieval_config = CodeRetrievalConfig(
                context_max_lines=os.environ.get("RETRIEVAL_CONTEXT_MAX_LINES", "200")
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
            retrieval = code_retrieval_config
        )