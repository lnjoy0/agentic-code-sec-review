import logging
import asyncio
import re
import difflib
from langchain_core.runnables import RunnableConfig
from langchain_core.prompts import ChatPromptTemplate
from typing import Dict, Any, List
from pydantic import ValidationError

from sec_reviewer.scanners.heuristic_scanner import HeuristicScanner
from sec_reviewer.scanners.semantic_scanner import LLMSemanticScanner
from sec_reviewer.core.expert_agents import get_model_bound_tools, save_request_messages
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

    max_rounds = config['configurable'].get('agent_config').agent_max_rounds
    llm_config = config['configurable'].get('llm_config')

    structured_llm = get_model_bound_tools(llm_config, role_name="Router", tools=[LLMRouteDecision])
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", ROUTER_PROMPT),
        ("human", "漏洞报告:\n {issue}\nrejected_by: {rejected_by}\nrejection_reason: {rejection_reason}\n请分析并返回合适的专家名称。")
    ])
    semaphore = asyncio.Semaphore(25)

    scanner_reports = state.get("scanner_reports", {})
    rejection_history = state.get("rejection_history", {})
    audit_results = state.get("audit_results", [])

    # 子图运行过程中，主图是同步阻塞的，所以每次路由节点被触发时，之前已经处理完成的漏洞会被写入audit_results中
    # 而不在audit_results中的漏洞，说明其被退回
    processed_issue_ids = [res.id for res in audit_results]
    
    routing_decisions: List[RouteTask] = []
    soft_route_tasks = []
    unique_issues = []
    
    # 漏洞去重
    ordered_scanners = sorted(scanner_reports.keys(), key=lambda k: 0 if k.lower() == 'llm' else 1) # 先处理 LLM 扫描器的结果
    for scanner_name in ordered_scanners:
        issues = scanner_reports[scanner_name]
        for issue in issues:
            id = issue.id
            is_unique = True
            start_line = issue.snippet_region.start_line
            end_line = issue.snippet_region.end_line

            for _, existing_issue in unique_issues:
                e_start_line = existing_issue.snippet_region.start_line
                e_end_line = existing_issue.snippet_region.end_line
                
                has_intersection = not (end_line < e_start_line or start_line > e_end_line)
                if issue.path == existing_issue.path and has_intersection:
                    if issue.name and existing_issue.name:
                        if _is_text_similar(issue.name, existing_issue.name):
                            is_unique = False
                    elif _is_text_similar(issue.snippet_text, existing_issue.snippet_text):
                        is_unique = False

                    if not is_unique:
                        if issue.message not in existing_issue.message:
                            existing_issue.message += f"\n\n[{scanner_name} 扫描器补充报告]:\n{issue.message}"
                    
                            logger.info(
                                f"  [Deduplication] 漏洞 issue[{id}] ({issue.name or issue.cwe}) "
                                f"与之前的漏洞 issue[{existing_issue.id}] ({existing_issue.name or existing_issue.cwe}) 路径相同，名称或代码片段相似。"
                                f"将被视为重复漏洞，不再路由，同时将该漏洞的描述信息合并到之前的漏洞中。"
                            )
                            break

            if is_unique:
                unique_issues.append((scanner_name, issue))
            else:
                continue # 重复的漏洞不再路由

    # 去重后的待研判漏洞总数
    total_target_issues = len(unique_issues)
    
    # 路由决策
    for scanner_name, issue in unique_issues:
        expert_name = None
        id = issue.id

        # 过滤已处理过的漏洞
        if id in processed_issue_ids:
            continue

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
            logger.info(f"  [Hard Route] 漏洞 issue[{id}] ({issue.name or issue.cwe}) 被规则路由到 {expert_name}，但它在历史退回记录中，已被退回。因此进入软路由流程...")
            expert_name = None

        if expert_name:
            logger.info(f"  [Hard Route] 命中字典映射: issue[{id}] ({issue.name or issue.cwe}) -> {expert_name}")
            routing_decisions.append(_build_task(expert_name, issue, max_rounds, rejection_history))
        else:
            # 软路由，先将协程任务收集起来，稍后并发执行
            logger.info(f"  [Soft Route] 准备发起大模型路由分析: issue[{id}] ({issue.name or issue.cwe})")
            chain = prompt | structured_llm
            inputs = {
                "issue": issue.model_dump_json(),
                "rejected_by": ", ".join(rejected_by),
                "rejection_reason": rejection_reason
            }

            coro = _route_with_save(chain, prompt, inputs, id, semaphore)
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
                    try:
                        decision = LLMRouteDecision(**tool_args)
                        expert_name = decision.expert_name
                        if expert_name in task["rejected_by"]:
                            logger.error(f"  [Soft Route] LLM 决策失败，专家 {expert_name} 已在退回记录中，issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) 降级为通用专家。")
                            expert_name = "General_Expert"
                        else:
                            logger.info(f"  [Soft Route] LLM 决策: issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) -> {expert_name} (原因: {decision.reason})\n原始消息: {result}")
                    except ValidationError as e:
                        logger.error(f"  [Soft Route] LLM 路由失败，issue[{task['id']}] ({task['issue'].name or task['issue'].cwe}) 被分配给通用专家。错误: LLM 的输出的参数未通过 Pydantic 校验，输出内容为 {str(result)}，报错 {e}")

            routing_decisions.append(_build_task(expert_name, task["issue"], max_rounds, rejection_history))

    return {"routing_decisions": routing_decisions, "total_target_issues": total_target_issues}

async def _route_with_save(chain, prompt, inputs, issue_id, semaphore):
    """并发执行 LLM 请求和消息保存逻辑"""
    async with semaphore:
        async def save_msg():
            try:
                prompt_value = await prompt.ainvoke(inputs)
                raw_messages = prompt_value.to_messages()
                await save_request_messages(raw_messages, 'router', f'issue({issue_id})_route')
            except Exception as e:
                logger.warning(f"⚠️ 保存 issue[{issue_id}] 请求消息时发生错误: {e}")

        save_task = asyncio.create_task(save_msg())

        try:
            result = await asyncio.wait_for(chain.ainvoke(inputs), timeout=45.0)
            return result
        finally:
            await save_task

def _build_task(expert_name, issue, max_rounds, rejection_history):
    return {
        "expert_name": expert_name,
        "agent_state_input": {
            "issue": issue,
            "messages": [],
            "remaining_rounds": max_rounds,
            "viewed_docs": [],
            "rejection_history": rejection_history,
            "draft_result": None,
            "critical_history": [],
            "audit_results": []
        }
    }

def _normalize_text(text: str) -> str:
    if not text:
        return ""
    # 移除所有空白字符并转小写
    return re.sub(r'\s+', '', text).lower()

def _is_text_similar(snippet1: str, snippet2: str, threshold: float = 0.6) -> bool:
    norm_1 = _normalize_text(snippet1)
    norm_2 = _normalize_text(snippet2)
    
    if not norm_1 or not norm_2:
        return False
        
    # 如果存在包含关系，直接认定为重复
    if norm_1 in norm_2 or norm_2 in norm_1:
        return True
        
    # 计算字符串的相似度比率
    similarity = difflib.SequenceMatcher(None, norm_1, norm_2).ratio()
    return similarity >= threshold

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
            severity = result.details.severity.upper()
            confidence = result.details.confidence
            reason = result.details.analysis_reasoning
            defense_checks = result.details.defense_checks
            attack_scenario = result.details.attack_scenario
            remediation = result.details.remediation

            emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "💡", "LOW": "ℹ️"}
            markdown_body = f"""### 🤖 安全漏洞审查: {name}

| 属性 | 详情 |
| :--- | :--- |
| **严重程度** | {emoji[severity]} `{severity}` |
| **置信度** | 🎯 `{confidence * 100:.1f}%` |

#### 🔍 研判分析
{reason}

#### 🛡️ 防御检查
{defense_checks}

#### 🚀 攻击场景
{attack_scenario}

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
    
    severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    comments.sort(key=lambda x: severity_order.get(x.severity, 99))

    logger.info(f"✅ 研判结果汇总完毕，共生成 {len(comments)} 条评论。")

    return {'final_comment': comments}