import logging
import asyncio
from langchain_core.runnables import RunnableConfig
from langchain_core.prompts import ChatPromptTemplate
from typing import Dict, Any, List

from sec_reviewer.scanners.heuristic_scanner import HeuristicScanner
from sec_reviewer.scanners.semantic_scanner import LLMSemanticScanner
from sec_reviewer.core.expert_agents import get_model_bound_tools
from sec_reviewer.core.data_models import LLMRouteDecision, RouteTask, AuditState, ReviewComment, LLMScanReport
from sec_reviewer.knowledge_base.sys_prompts import ROUTER_PROMPT
from sec_reviewer.knowledge_base.cwe_category import (INJECTION_CWES, LOGIC_IDENTITY_CWES,
                                                      DATA_ASSET_CWES, INFRA_SUPPLY_CWES)


logger = logging.getLogger(__name__)


async def heuristic_scanner_node(state: AuditState, config: RunnableConfig) -> Dict[str, Any]:
    """启发式工具扫描器节点"""
    logger.info("[Node] 运行启发式扫描器 (Semgrep, Gitleaks, Trivy)...")

    scanner_config = config['configurable'].get('scanner_config')
    retrieval_config = config['configurable'].get('retrieval_config')
    patched_files = state['patched_files']

    heuristic_scanner = HeuristicScanner(scanner_config, retrieval_config)
    heuristic_report = await heuristic_scanner.get_report(patched_files)

    return {'scanner_reports': heuristic_report}

async def semantic_scanner_node(state: AuditState, config: RunnableConfig) -> Dict[str, Any]:
    """基于LLM的语义扫描器节点"""
    logger.info("[Node] 运行基于LLM的语义扫描器...")

    scanner_config = config['configurable'].get('scanner_config')
    llm_config = config['configurable'].get('llm_config')
    retrieval_config = config['configurable'].get('retrieval_config')
    patched_files = state['patched_files']

    scanner_llm = get_model_bound_tools(llm_config, role_name="Scanner", tools=[LLMScanReport])
    semantic_scanner = LLMSemanticScanner(scanner_config, retrieval_config, scanner_llm)
    semantic_report = await semantic_scanner.get_report(patched_files)

    return {'scanner_reports': semantic_report}

# 硬路由规则字典
HARD_ROUTING_RULES = {
    "gitleaks": "Data_Asset_Expert",
    "trivy": "Infra_Supply_Expert",
    "semgrep": {
        **{key: "Injection_Expert" for key in INJECTION_CWES},
        **{key: "Logic_Identity_Expert" for key in LOGIC_IDENTITY_CWES},
        **{key: "Data_Asset_Expert" for key in DATA_ASSET_CWES},
        **{key: "Infra_Supply_Expert" for key in INFRA_SUPPLY_CWES}
    }
}

async def dynamic_router_node(state: AuditState, config: RunnableConfig):
    """路由判定节点：执行硬/软路由，生成分发任务清单"""
    logger.info("\n[Router Node] 开始漏洞路由分析...")

    max_turns = config['configurable'].get('agent_config').max_turns
    llm_config = config['configurable'].get('llm_config')

    # router 正常输出只有专家名和简短原因，加上 max_tokens 以防止无限生成
    structured_llm = get_model_bound_tools(llm_config, role_name="Router", tools=[LLMRouteDecision], max_tokens=800)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", ROUTER_PROMPT),
        ("human", "漏洞报告:\n {issue}\nrejected_by: {rejected_by}\nrejection_reason: {rejection_reason}\n请分析并返回合适的专家名称。")
    ])

    scanner_reports = state.get("scanner_reports", {})
    rejection_history = state.get("rejection_history", {})
    audit_results = state.get("audit_results", [])

    # 子图运行过程中，主图是同步阻塞的，所以每次路由节点被触发时，之前已经处理完成的漏洞会被写入audit_results中
    # 而不在audit_results中的漏洞，说明其被退回
    processed_issue_ids = [res.id for res in audit_results]
    
    routing_decisions: List[RouteTask] = []
    soft_route_tasks = []
    
    for scanner_name, issues in scanner_reports.items():
        for issue in issues:
            expert_name = None
            id = issue.id

            if id in processed_issue_ids:
                continue # 已经处理过的漏洞不再路由

            rejected_by = []
            rejection_reason = ""
            if id in rejection_history:
                rejection_reason = "\n该漏洞已被以下专家退回，请参考其退回理由进行重新路由：\n"
                for record in rejection_history[id]:
                    rejected_by.append(record['expert'])
                    rejection_reason += f"- 专家 [{record['expert']}]: {record['reason']}\n"

            # 优先进行硬路由，按照字典规则直接映射到专家节点
            rule = HARD_ROUTING_RULES.get(scanner_name, None)
            if isinstance(rule, str):
                expert_name = rule
            elif isinstance(rule, dict):
                cwe = issue.cwe.lower().split(':')[0]
                for rule_cwe, mapped_expert in rule.items():
                    if rule_cwe == cwe:
                        expert_name = mapped_expert
                        break

            if expert_name in rejected_by:
                logger.info(f"  [Hard Route] 漏洞 issue[{id}] ({issue.name or issue.cwe}) 被规则路由到 {expert_name}，但它在历史退回记录中，已被退回过。")
                expert_name = None

            if expert_name:
                logger.info(f"  [Hard Route] 命中字典映射: issue[{id}] ({issue.name or issue.cwe}) -> {expert_name}")
                routing_decisions.append(_build_task(expert_name, issue, max_turns, rejection_history))
            else:
                # 软路由，先将协程任务收集起来，稍后并发执行
                logger.info(f"  [Soft Route] 准备发起大模型路由分析: issue[{id}] ({issue.name or issue.cwe})")
                chain = prompt | structured_llm
                coro = asyncio.wait_for(
                    chain.ainvoke({
                        "issue": issue.model_dump_json(indent=2),
                        "rejected_by": ", ".join(rejected_by),
                        "rejection_reason": rejection_reason
                    }), 
                    timeout=45.0 # 设置超时限制，防止 Router 持续输出无意义内容
                )
                soft_route_tasks.append({
                    "id": id,
                    "issue": issue,
                    "coro": coro,
                    "rejected_by": rejected_by
                })

    # 并发执行所有软路由请求
    if soft_route_tasks:
        logger.info(f"  [Soft Route] 正在并发处理 {len(soft_route_tasks)} 个 LLM 路由请求...")
        coros = [task["coro"] for task in soft_route_tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for task, result in zip(soft_route_tasks, results):
            expert_name = "General_Expert"
            if isinstance(result, Exception):
                logger.error(f"  [Soft Route] LLM 路由失败，issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) 被分配给通用专家。错误: {result}")
                logger.error(task['issue'])
            else:
                tool_name = result.tool_calls[0]['name']
                tool_args = result.tool_calls[0]['args']

                if tool_name != "LLMRouteDecision":
                    logger.error(f"  [Soft Route] LLM 路由失败，issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) 被分配给通用专家。错误: LLM 的输出未调用 LLMRouteDecision 工具，输出内容为 {str(result)}")
                else:
                    decision = LLMRouteDecision(**tool_args)
                    expert_name = decision.expert_name
                    if expert_name in task["rejected_by"]:
                        logger.error(f"  [Soft Route] LLM 决策失败，专家 {expert_name} 已在退回记录中，issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) 降级为通用专家。")
                        expert_name = "General_Expert"
                    else:
                        logger.info(f"  [Soft Route] LLM 决策: issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) -> {expert_name} (原因: {decision.reason})")
            
            routing_decisions.append(_build_task(expert_name, task["issue"], max_turns, rejection_history))

    return {"routing_decisions": routing_decisions}

def _build_task(expert_name, issue, max_turns, rejection_history):
    return {
        "expert_name": expert_name,
        "agent_state_input": {
            "issue": issue,
            "remaining_turns": max_turns,
            "viewed_docs": [],
            "messages": [],
            "rejection_history": rejection_history,
            "audit_results": []
        }
    }            

def aggregate_and_check_node(state: AuditState):
    """该节点仅用来汇聚所有 Agent 子图的执行结果。"""
    logger.info("[Aggregate and Check] 所有被分配的专家已执行完毕。检查是否需要进入下一轮路由...")
    return {}

def get_comment_node(state: AuditState, config: RunnableConfig):
    """生成评论内容节点"""
    logger.info("=== 所有专家研判完毕，汇总结果 ===")

    audit_results = state['audit_results']

    comments = []
    for result in audit_results:
        if result.details.verdict == "True Positive":
            name = result.details.name
            severity = result.details.severity
            confidence = result.details.confidence
            reason = result.details.analysis_reasoning
            remediation = result.details.remediation

            emoji = {"critical": "🚨", "high": "⚠️", "medium": "💡", "low": "ℹ️"}
            markdown_body = f"""### 🤖 安全漏洞审查: {name}

| 属性 | 详情 |
| :--- | :--- |
| **严重程度** | {emoji[severity]} `{severity.upper()}` |
| **置信度** | 🎯 `{confidence * 100:.1f}%` |

#### 🔍 研判分析
{reason}

#### 🛠️ 修复建议
{remediation}
"""

            comment = ReviewComment(
                body=markdown_body,
                path=result.path,
                start_line=result.start_line,
                end_line=result.end_line,
                severity=result.details.severity
            )
            comments.append(comment)
    
    logger.info(f"✅ 研判结果汇总完毕，共生成 {len(comments)} 条评论。")

    return {'final_comment': comments}