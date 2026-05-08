"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

import operator
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, TypedDict, Annotated
from unidiff import PatchedFile
from enum import Enum
from langgraph.graph.message import BaseMessage, add_messages
from pydantic import BaseModel, Field, model_validator
from typing import Literal


@dataclass
class PRDetails:
    """Details of a pull request."""
    owner: str
    repo: str
    pull_number: int
    title: str
    description: str
        
    @property
    def repo_full_name(self) -> str:
        """Get the full repository name."""
        return f"{self.owner}/{self.repo}"


@dataclass
class FileInfo:
    """Information about a file in a diff."""
    path: str
    old_path: Optional[str] = None
    is_new_file: bool = False
    is_renamed_file: bool = False
    
    @property
    def is_binary(self) -> bool:
        """Check if the file is likely binary based on extension."""
        binary_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', 
            '.tar', '.gz', '.exe', '.dll', '.so', '.dylib'
        }
        return any(self.path.lower().endswith(ext) for ext in binary_extensions)
    
    @property
    def file_extension(self) -> str:
        """Get the file extension."""
        return self.path.split('.')[-1].lower() if '.' in self.path else ''


@dataclass
class HunkInfo:
    """Information about a hunk in a diff."""
    source_start: int
    source_length: int
    target_start: int
    target_length: int
    content: str
    header: str = ""
    lines: List[str] = field(default_factory=list)


@dataclass
class DiffFile:
    """Represents a file in a diff."""
    file_info: FileInfo
    hunks: List[HunkInfo] = field(default_factory=list)
    
    @property
    def total_additions(self) -> int:
        """Count total added lines."""
        return sum(1 for hunk in self.hunks for line in hunk.lines if line.startswith('+'))
    
    @property
    def total_deletions(self) -> int:
        """Count total deleted lines."""
        return sum(1 for hunk in self.hunks for line in hunk.lines if line.startswith('-'))


class ReviewPriority(Enum):
    """Priority levels for code review comments."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ReviewComment:
    """A code review comment."""
    body: str
    path: str
    position: int
    line_number: Optional[int] = None
    category: Optional[str] = None
    priority: Optional[ReviewPriority] = None
    suggestion: Optional[str] = None
    
    def to_github_comment(self) -> Dict[str, Any]:
        """Convert to GitHub API format."""
        return {
            "body": self.body,
            "path": self.path,
            "position": self.position
        }


@dataclass
class ReviewResult:
    """Result of a code review."""
    pr_details: PRDetails
    comments: List[ReviewComment] = field(default_factory=list)
    processed_files: int = 0
    skipped_files: int = 0
    errors: List[str] = field(default_factory=list)
    processing_time: Optional[float] = None
    
    @property
    def total_comments(self) -> int:
        """Get total number of comments."""
        return len(self.comments)
    
    @property
    def comments_by_priority(self) -> Dict[ReviewPriority, int]:
        """Get comment count by priority."""
        counts = {priority: 0 for priority in ReviewPriority}
        for comment in self.comments:
            counts[comment.priority] += 1
        return counts
    
    @property
    def success(self) -> bool:
        """Check if review was successful."""
        return len(self.errors) == 0


@dataclass
class AnalysisContext:
    """Context information for code analysis."""
    pr_details: PRDetails
    file_info: FileInfo
    related_files: List[str] = field(default_factory=list)
    project_context: Optional[str] = None
    language: Optional[str] = None
    
    @property
    def is_test_file(self) -> bool:
        """Check if this is a test file."""
        test_patterns = ['test_', '_test.', 'spec_', '_spec.', '/test/', '/tests/']
        return any(pattern in self.file_info.path.lower() for pattern in test_patterns)


class ScannedIssue(BaseModel):
    """扫描器报告的漏洞结构"""
    id: int
    path: str
    message: str
    cwe: Optional[str] = None
    snippet_region: Dict[str, int] = {
        "start_line": int,
        "end_line": int,
        "start_column": int,
        "end_column": int
    }
    snippet_text: str
    context: str


class LLMRouteDecision(BaseModel):
    """【输出格式要求】Semantic Router 的输出结构"""
    expert_name: Literal[
        "Injection_Expert",
        "Data_Asset_Expert",
        "Infra_Supply_Expert",
        "Logic_Security_Expert",
        "General_Expert"
    ] = Field(
        ..., 
        description="最适合处理该漏洞的专家名称。"
    )
    reason: str = Field(..., description=("简短地说明为什么选择这个专家。必须涵盖以下要点：\n"
                                          "1. 你提取到的漏洞核心技术本质是什么。\n"
                                          "2. 为什么选择该专家。"))


class RouteTask(TypedDict):
    """用于记录单个路由分发任务的结构"""
    expert_name: str
    agent_state_input: Dict[str, Any]


class Rejection(BaseModel):
    """【拒绝处理该漏洞】当你认为分配给你的漏洞不属于你的职能范围时，调用此工具将任务退回给 Router。"""
    reject_reason: str = Field(
        ..., 
        description="说明为什么拒绝处理该漏洞，指出它实际上属于什么类型的安全问题。"
    )


class RejectionRecord(TypedDict):
    """拒绝某个漏洞的专家名称及其原因"""
    expert: str
    reason: str


class AuditResult(BaseModel):
    """【提交最终研判结果】当你完成漏洞研判后，必须调用此工具提交你的最终研判定论。"""
    
    verdict: Literal["True Positive", "False Positive"] = Field(
        ..., 
        description="最终判定结果。必须是 'True Positive'（确认存在漏洞）或 'False Positive'（确认是误报）。"
    )
    
    severity: Literal["none", "low", "medium", "high", "critical"] = Field(
        ..., 
        description=(
            "漏洞严重程度等级：\n"
            "- none: 无风险，只有当 verdict 为 'False Positive' 时，严重性才允许设为 none。\n"
            "- low: 风险较低，利用条件极其苛刻，或影响范围极小。\n"
            "- medium: 中等风险，具有一定的利用价值，可能导致局部数据泄露。\n"
            "- high: 高风险，容易被利用，可能导致关键业务受损或敏感数据大量泄露。\n"
            "- critical: 严重风险，可导致远程代码执行（RCE）、全库泄露或系统完全失控。"
        )
    )

    confidence: float = Field(
        ..., 
        ge=0.0, 
        le=1.0, 
        description="判定置信度。范围是 0.0 到 1.0。"
    )
    
    analysis_reasoning: str = Field(
        ..., 
        min_length=50,
        description=(
            "详细的研判逻辑推导过程。必须涵盖以下要点：\n"
            "1. 漏洞触发机理：简述该类漏洞成立的核心前提（如：特定的危险配置、不受信任的数据流、或不安全的函数调用）。\n"
            "2. 上下文核查：结合当前代码片段，分析是否确实满足上述触发条件（例如：是否存在防御配置、变量是否真正受控、依赖版本是否匹配）。\n"
            "3. 如果判定为误报，必须说明排除逻辑（如：已有前置校验、仅用于测试环境等）；如果判定为真实漏洞，必须给出该漏洞的利用方法。" 
        )
    )
    
    remediation: str = Field(
        default="", 
        description="修复代码或配置建议。只有当 verdict 为 'True Positive' 时才提供；若为 'False Positive' 则保持为空字符串。"
    )

    @model_validator(mode='after')
    def validate_logic(self) -> 'AuditResult':
        # 真实漏洞时必须有修复建议
        if self.verdict == "True Positive" and not self.remediation.strip():
            raise ValueError("校验失败：判定为 True Positive 时，必须提供具体的 remediation 修复建议代码。")
        
        # 确保误报时没有修复建议
        if self.verdict == "False Positive" and self.remediation.strip():
            self.remediation = "" 

        # 确保真实漏洞的严重性不能为 none
        if self.verdict == "True Positive" and self.severity == "none":
            raise ValueError("逻辑矛盾：当判定为 True Positive 时，必须选择具体的风险等级，不能为 'none'。")
            
        return self


# 自定义的 Reducer
def merge_rejection_history(old_hist: Dict, new_hist: Dict) -> Dict:
    """用于合并拒绝历史记录"""
    merged = old_hist.copy() 

    for issue_id, records in new_hist.items():
        if issue_id in merged:
            # 用old_hist的专家名作为键，构成字典
            combined_map = {rec['expert']: rec for rec in merged[issue_id]}
            # 将new_hist的记录写入字典，通过专家名来去重和新增
            for record in records:
                combined_map[record['expert']] = record 

            merged[issue_id] = list(combined_map.values())
        else:
            merged[issue_id] = records
    return merged


# 主图状态
class AuditState(TypedDict):
    patched_files: List[PatchedFile]
    scanner_reports: Annotated[Dict[str, List[Dict]], lambda x,y: {**x, **y}] # 合并不同扫描器的报告
    routing_decisions: List[RouteTask]
    rejection_history: Annotated[Dict[int, List[RejectionRecord]], merge_rejection_history] # 记录某个漏洞被哪些专家拒绝
    audit_results: Annotated[List[Dict], operator.add]
    final_comment: List[ReviewComment]


# 单个Agent的子图状态
class AgentState(TypedDict):
    issue: Dict[str, Any]
    messages: Annotated[list[BaseMessage], add_messages] # add_messages自动合并多轮对话
    remaining_turns: int
    rejection_history: Annotated[Dict[int, List[RejectionRecord]], merge_rejection_history]
    audit_results: Annotated[List[Dict], operator.add]