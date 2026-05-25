import logging
from langchain_core.runnables import RunnableConfig
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json

from scanners import HeuristicScanner
from core.data_models import AuditState, ReviewComment
from core.config import LLMConfig
from core.data_models import LLMRouteDecision, RouteTask
from knowledge_base.sys_prompts import ROUTER_PROMPT


logger = logging.getLogger(__name__)


class ModelProvider:

    @staticmethod
    def get_model(config: LLMConfig, role_name: str):
        model = ChatOpenAI(
            model=config.model_name,
            openai_api_base=config.base_url,
            openai_api_key=config.api_key,
            temperature=config.Role[role_name].temperature,
            top_p=config.Role[role_name].top_p,
            max_retries=3,
            seed=42
        )
        return model


async def heuristic_scanner_node(state: AuditState, config: RunnableConfig) -> Dict[str, Any]:
    """启发式工具扫描器节点"""
    logger.info("[Node] 运行启发式扫描器 (Semgrep, Gitleaks, Trivy)...")

    scanner_config = config['configurable'].get('scanner_config')
    context_config = config['configurable'].get('context_config')
    patched_files = state['patched_files']

    heuristic_scanner = HeuristicScanner(scanner_config, context_config)
    heuristic_report = await heuristic_scanner.get_report(patched_files)

    return {'scanner_reports': heuristic_report}

# 硬路由规则字典
INJECTION_CWES = ["cwe-89", "cwe-78", "cwe-79"]
LOGIC_IDENTITY_CWES = ["cwe-284", "cwe-285", "cwe-306"]

HARD_ROUTING_RULES = {
    "gitleaks": "Data_Asset_Expert",
    "trivy": "Infra_Supply_Expert",
    "semgrep": {
        **{key: "Injection_Expert" for key in INJECTION_CWES},
        **{key: "Logic_Identity_Expert" for key in LOGIC_IDENTITY_CWES}
    }
}

def dynamic_router_node(state: AuditState, config: RunnableConfig):
    """路由判定节点：执行硬/软路由，生成分发任务清单"""
    logger.info("\n[Router Node] 开始漏洞路由分析...")

    max_turns = config['configurable'].get('agent_config').max_turns
    llm_config = config['configurable'].get('llm_config')

    router_llm = ModelProvider.get_model(llm_config, role_name="Router")
    structured_router = router_llm.with_structured_output(LLMRouteDecision)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", ROUTER_PROMPT),
        ("human", "漏洞报告: {issue}\nrejected_by: {rejected_by}\nrejection_reason: {rejection_reason}\n请分析并返回合适的专家名称。")
    ])

    scanner_reports = state.get("scanner_reports", {})
    rejection_history = state.get("rejection_history", {})
    audit_results = state.get("audit_results", [])

    # 子图运行过程中，主图是同步阻塞的，所以每次路由节点被触发时，之前已经处理完成的漏洞会被写入audit_results中
    # 而不在audit_results中的漏洞，说明其被退回
    processed_issue_ids = [res.get("id") for res in audit_results]
    
    routing_decisions: List[RouteTask] = []
    
    index = 0
    for scanner_name, issues in scanner_reports.items():
        for issue in issues:
            expert_name = None
            cwe = issue.get("cwe", "").lower().split(':')[0]

            index += 1
            issue['id'] = index # 给每个 issue 分配一个唯一 ID，从 1 开始递增

            if index in processed_issue_ids:
                continue # 已经处理过的漏洞不再路由

            rejected_by = []
            rejection_reason = ""
            if index in rejection_history:
                rejection_reason = "\n该漏洞已被以下专家退回，请参考其退回理由进行重新路由：\n"
                for record in rejection_history[index]:
                    rejected_by.append(record['expert'])
                    rejection_reason += f"- 专家 [{record['expert']}]: {record['reason']}\n"
            
            # 优先进行硬路由，按照字典规则直接映射到专家节点
            rule = HARD_ROUTING_RULES[scanner_name]
            if isinstance(rule, str):
                expert_name = rule
            elif isinstance(rule, dict):
                for rule_cwe, mapped_expert in rule.items():
                    if rule_cwe == cwe:
                        expert_name = mapped_expert
                        break

            if expert_name in rejected_by:
                logger.info(f"  [Hard Route] 漏洞 issue[{index}] ({cwe}) 被规则路由到 {expert_name}，但它在历史退回记录中，已被退回过。")
                expert_name = None # 进入软路由

            # 进行软路由，使用 LLM 分析漏洞特征，判断最适合的专家，用于处理没有明确规则覆盖的情况
            if not expert_name:
                logger.info(f"  [Soft Route] 触发大模型路由分析: issue[{index}] ({cwe})")
                chain = prompt | structured_router
                try:
                    decision = chain.invoke({
                        "issue": issue, 
                        "rejected_by": rejected_by,
                        "rejection_reason": rejection_reason
                    })

                    expert_name = decision.expert_name
                    if expert_name in rejected_by:
                        logger.error(f"    -> LLM 决策失败，专家 {expert_name} 已在退回记录中，降级为通用专家。")
                        expert_name = "General_Expert"

                    logger.info(f"    -> LLM 决策: {expert_name} (原因: {decision.reason})")
                except Exception as e:
                    logger.error(f"    -> LLM 路由失败，降级为通用专家。错误: {e}")
                    expert_name = "General_Expert"
            else:
                logger.info(f"  [Hard Route] 命中字典映射: issue[{index}] -> {expert_name}")

            routing_decisions.append({
                "expert_name": expert_name,
                "agent_state_input": {
                    "issue": issue,
                    "remaining_turns": max_turns,
                    "viewed_docs": [],
                    "messages": [],
                    "rejection_history": rejection_history,
                    "audit_results": []
                }
            })
            
    return {"routing_decisions": routing_decisions}

def aggregate_and_check_node(state: AuditState):
    """该节点仅用来汇聚所有 Agent 子图的执行结果。"""
    logger.info("[Aggregate and Check] 所有被分配的专家已执行完毕。检查是否需要进入下一轮路由...")
    return {}

def get_comment_node(state: AuditState, config: RunnableConfig) -> List[ReviewComment]:
    """生成评论内容节点"""
    logger.info("=== 所有专家研判完毕，汇总结果 ===")

    results = state['refined_results']
    patched_files = state['patched_files']

    comments = []
    for tool, tool_results in results.items():                        
        comment = ReviewComment(
            body=json.dumps(tool_results[:100], indent=4),
            path=patched_files[0].path,
            position=1
        )
        comments.append(comment)
    
    return {'final_comment': comments}