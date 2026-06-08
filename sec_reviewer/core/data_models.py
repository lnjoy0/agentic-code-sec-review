"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

from uuid import uuid4
from typing import List, Dict, Any, Optional, TypedDict, Annotated
from unidiff import PatchedFile
from langgraph.graph.message import BaseMessage, add_messages
from pydantic import BaseModel, Field, model_validator
from typing import Literal


class PRDetails(BaseModel):
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


class ReviewComment(BaseModel):
    """A code review comment."""
    body: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1) # 指定在第几行写评论，这是文件中的绝对行号
    severity: Literal["low", "medium", "high", "critical"]


class LLMScannedIssue(BaseModel):
    reasoning_process: str = Field(
        ...,
        description=(
            "【有机思维链】在得出最终结论前，请写下一段自然、连续的审计推理草稿（像侦探自言自语一样）。\n"
            "在思考时，请将以下“悲观假设”心法融入你的推理流中，但【绝对不要】在输出时使用序号或列表格式：\n"
            "- 留意当前片段新增的变量、外部输入或危险函数调用。\n"
            "- 假设不在当前范围内的变量是恶意的，假设未知的配置是不安全的。\n"
            "- 观察当前可见代码中是否缺少了拦截这些危险的防线（过滤、转义等）。\n"
            "- 明确提炼出需要下游专家去追查的疑点。\n"
            "要求：输出一段逻辑连贯的自然语言段落，展现你发现疑点、提出假设并指出防御缺失的动态思考过程。"        )
    )
    name: str = Field(
        ...,
        description="简短的漏洞名称，例如 'SQL Injection'、'Command Injection'、'Race Condition' 等"
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ..., 
        description=("预估的漏洞严重程度，可选值：critical, high, medium, low")
    )
    start_line: int = Field(
        ...,
        ge=1,
        description="该漏洞代码在文件中的起始行号"
    )
    end_line: int = Field(
        ...,
        ge=1,
        description="该漏洞代码在文件中的终止行号"
    )
    vulnerable_code_snippet: str = Field(
        ...,
        description="触发该漏洞的核心代码片段（仅需一到两行即可），用于辅助精准定位"
    )
    confidence_score: int = Field(
        ...,
        ge=1, le=10,
        description="你对该漏洞实际存在的置信度打分 (1-10分)，10分为极大概率存在"
    )
    information: str = Field(
        ...,
        description="详细描述该漏洞的信息：包括原理、缺陷、可能的利用方式等"
    )


class LLMScanReport(BaseModel):
    """【提交漏洞扫描结果】你的输出【必须且只能】调用此工具"""
    issues: List[LLMScannedIssue] = Field(
        ...,
        description="发现的潜在安全漏洞列表。**如果没有发现问题，必须返回空列表 `[]`**，绝对不能为了填充数据而捏造漏洞"
    )


class SnippetRegion(BaseModel):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: Optional[int] = Field(ge=1, default=None)
    end_column: Optional[int] = Field(ge=1, default=None)


class ScannedIssue(BaseModel):
    """扫描器报告的漏洞结构"""
    scanner: str
    id: str = Field(default_factory=lambda: str(uuid4())[:8]) # 自动生成短 id
    name: Optional[str] = None
    path: str
    message: str
    cwe: Optional[str] = None
    severity: Optional[str] = None
    confidence_score: Optional[int] = Field(ge=1, le=10, default=None)
    snippet_region: SnippetRegion
    snippet_text: str
    context: str


class LLMRouteDecision(BaseModel):
    """【提交路由决策结果】你的输出【必须且只能】调用此工具"""
    expert_name: Literal[
        "Injection_Expert",
        "Data_Asset_Expert",
        "Infra_Supply_Expert",
        "Logic_Identity_Expert",
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
    """
    【拒绝处理该漏洞】当你认为分配给你的漏洞不属于你的职能范围，应该由其他专家处理时，调用此工具将任务退回给 Router。
    """
    reject_reason: str = Field(
        ..., 
        description="说明为什么拒绝处理该漏洞，指出它实际上属于什么类型的安全问题。"
    )


class RejectionRecord(TypedDict):
    """拒绝某个漏洞的专家名称及其原因"""
    expert: str
    reason: str


class ExpertAuditResult(BaseModel):
    """【提交最终研判结果】当你完成漏洞研判后，【必须且只能】调用此工具提交你的最终研判定论。"""
    reasoning_process: str = Field(
        ...,
        description=(
            "【有机思维链】在得出最终结论前，请写下一段自然、连续的审计推理草稿（像侦探自言自语一样）。\n"
            "- 证据复盘：总结你通过工具收集到的关键上下文（如数据流转路径、关键业务逻辑、配置项状态或加密算法使用情况等）。\n"
            "- 漏洞机理核查：结合你所属领域的安全专业知识，一步步推演当前代码片段是否确实满足目标漏洞的触发条件。\n"
            "- 防御与缓解评估：排查代码或配置中是否存在现有的安全防御措施（如数据过滤、权限校验、白名单、安全基线等），并评估其是否充分且有效。\n"
            "- 最终推导：基于上述所有的事实与分析，明确推导出该告警是 True Positive（真实漏洞）还是 False Positive（误报）。\n"
            "要求：输出一段逻辑连贯的自然语言段落。"
        )
    )
    verdict: Literal["True Positive", "False Positive"] = Field(
        ..., 
        description="最终判定结果。必须是 'True Positive'（确认存在漏洞）或 'False Positive'（确认是误报）。"
    )
    name: str = Field(
        ...,
        description="简短的漏洞名称，例如 'SQL Injection'、'Command Injection'、'Race Condition' 等"
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
    vulnerability_analysis: str = Field(
        ..., 
        min_length=50,
        description=(
            "详细的漏洞分析报告。必须涵盖以下要点：\n"
            "1. 漏洞触发机理：简述该类漏洞成立的核心前提（如：特定的危险配置、不受信任的数据流、或不安全的函数调用）。\n"
            "2. 上下文核查：结合当前代码片段，分析是否确实满足上述触发条件（例如：是否存在防御配置、变量是否真正受控、依赖版本是否匹配）。\n"
            "3. 如果判定为误报，必须说明排除逻辑（如：已有前置校验、仅用于测试环境等）；如果判定为真实漏洞，必须给出该漏洞的可能利用方法。" 
        )
    )
    defense_checks: str = Field(
        default="",
        description=("列出你排查过的所有可能的防御措施，并解释为什么它们失效。只有当 verdict 为 'True Positive' 时才提供；若为 'False Positive' 则保持为空字符串。")
    )
    attack_scenario: str = Field(
        default="",
        description=(
            "漏洞的可能利用场景与攻击过程描述。只有当 verdict 为 'True Positive' 时才提供；若为 'False Positive' 则保持为空字符串。\n"
            "- 请详细描述攻击者可能如何利用该漏洞进行攻击，包括攻击前提、攻击步骤、可能的攻击载荷，以及攻击成功后可能造成的影响等。")
    )
    remediation: str = Field(
        default="", 
        description="修复代码或配置建议。只有当 verdict 为 'True Positive' 时才提供；若为 'False Positive' 则保持为空字符串。"
    )

    @model_validator(mode='after')
    def validate_logic(self) -> 'ExpertAuditResult':
        # 真实漏洞时，必须有防御检查、攻击场景、修复建议
        if self.verdict == "True Positive":
            if not self.defense_checks.strip():
                raise ValueError("校验失败：判定为 True Positive 时，必须提供具体的 defense_checks 防御检查。")
            if not self.attack_scenario.strip():
                raise ValueError("校验失败：判定为 True Positive 时，必须提供具体的 attack_scenario 攻击场景。")
            if not self.remediation.strip():
                raise ValueError("校验失败：判定为 True Positive 时，必须提供具体的 remediation 修复建议。")
        
        # 误报时，这些字段必须为空
        if self.verdict == "False Positive":
            if self.defense_checks.strip():
                self.defense_checks = ""
            if self.attack_scenario.strip():
                self.attack_scenario = ""
            if self.remediation.strip():
                self.remediation = ""

        # 确保真实漏洞的严重性不能为 none
        if self.verdict == "True Positive" and self.severity == "none":
            raise ValueError("逻辑矛盾：当判定为 True Positive 时，必须选择具体的风险等级，不能为 'none'。")
            
        return self


class CriticDecision(BaseModel):
    """【提交决策】当你完成分析后，【必须且只能】调用此工具提交你的最终决策。"""
    reasoning_process: str = Field(
        ...,
        description=(
             "【有机思维链】在得出最终结论前，请写下一段自然、连续的审计推理草稿（像侦探自言自语一样）。\n"
            "- 证据复核：专家智能体调用的工具轨迹是否足以支撑其结论？是否有断章取义或数据遗漏等？\n"
            "- 逻辑漏洞：专家的分析过程中是否存在未证实的假设？其推理是否符合安全常识？\n"
            "- 误报/漏报检验：如果专家判定为漏洞，是否忽略了代码中已存在的防御机制？如果判定为误报，是否过度信任了不可靠的外部输入？\n"
            "请严格基于上述三点进行沙盘推演，不要急于下结论。最终基于以上思考过程，明确得出应该 approve 还是 revise。" \
            "要求：输出一段逻辑连贯的自然语言段落。"
        )
    )
    decision: Literal["approve", "revise"] = Field(
        ...,
        description=("如果逻辑闭环且证据充分则选择 approve；如果发现逻辑漏洞或证据缺失则选择 revise。")
    )
    critique_reason: str = Field(
        default="", 
        description="如果不赞同专家的结论，请在这里详细地指出其存在的问题。这将直接发给专家作为驳回理由。如果 approve，则保持为空字符串。"
    )
    suggested_action: str = Field(
        default="",
        description="给专家的修改建议。如果 approve，则保持为空字符串。"
    )


class CriticalContent(BaseModel):
    """审查节点的决策记录"""
    round: int
    expert_verdict: str
    expert_reason: str
    review_decision: str
    review_decision_reason: str
    review_suggest: str


class IssueAuditResult(BaseModel):
    """每个漏洞的最终审计结果"""
    id: str
    expert: str
    path: str
    start_line: int
    end_line: int
    details: ExpertAuditResult


# 自定义的 Reducer
def merge_rejection_history(old_hist: Dict, new_hist: Dict) -> Dict:
    """用于合并拒绝历史记录"""
    if not old_hist:
        return new_hist.copy() if new_hist else {}

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
    scanner_reports: Annotated[Dict[str, List[ScannedIssue]], lambda x, y: {**(x or {}), **(y or {})}] # 合并不同扫描器的报告
    total_target_issues: int # 记录总的待研判漏洞数量
    routing_decisions: List[RouteTask]
    rejection_history: Annotated[Dict[int, List[RejectionRecord]], merge_rejection_history] # 记录某个漏洞被哪些专家拒绝
    audit_results: Annotated[List[IssueAuditResult], lambda x, y: (x or []) + (y or [])]
    final_comment: List[ReviewComment]


# 单个Agent的子图状态
class AgentState(TypedDict):
    issue: ScannedIssue
    messages: Annotated[list[BaseMessage], add_messages]
    remaining_rounds: int # 专家的剩余行动轮数
    viewed_docs: Annotated[List[str], lambda x, y: list({*(x or []), *(y or [])})]
    rejection_history: Annotated[Dict[int, List[RejectionRecord]], merge_rejection_history]
    draft_result: Optional[IssueAuditResult]
    critical_history: Annotated[List[CriticalContent], lambda x, y: (x or []) + (y or [])]
    audit_results: Annotated[List[IssueAuditResult], lambda x, y: (x or []) + (y or [])]