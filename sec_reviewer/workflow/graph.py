from langgraph.graph import StateGraph, START, END
from langgraph.types import Send
from typing import Literal
import logging
import os

from sec_reviewer.tools.code_retriever import CodeRetriever
from sec_reviewer.tools.project_analyzer import ProjectAnalyzer
from sec_reviewer.tools.knowledge_retriever import SecKnowledgeBase
from sec_reviewer.core.data_models import AuditState
from sec_reviewer.core.config import CodeRetrievalConfig
from sec_reviewer.core.expert_agents import (InjectionExpert, DataAssetExpert, InfraSupplyExpert,
                                             LogicIdentityExpert, GeneralExpert)
from .nodes import (heuristic_scanner_node, semantic_scanner_node,
                   aggregate_and_check_node, dynamic_router_node, get_comment_node)


logger = logging.getLogger(__name__)


def distribute_issues_edge(state: AuditState):
    """读取由 router_node 生成的决策列表，触发 Map 并发执行"""
    sends = []
    decisions = state.get("routing_decisions", [])
    
    for decision in decisions:
        expert_name = decision["expert_name"].lower()
        agent_state_input = decision["agent_state_input"]
        
        sends.append(Send(expert_name, agent_state_input)) # Send api是一个map-reduce操作
        
    return sends

def check_rejection_edge(state: AuditState) -> Literal["dynamic_router", "__end__"]:
    """检查是否存在被退回的漏洞"""
    total_target_issues = state.get("total_target_issues", 0)
    audit_results = state.get("audit_results", [])
        
    # 已经拿到最终研判结果的漏洞数
    finished_issues = len(audit_results)
    
    if finished_issues < total_target_issues:
        logger.info(f"🔄 检测到退回！进度 {finished_issues}/{total_target_issues}。重定向回 Router...")
        return "dynamic_router"
    
    logger.info("✅ 所有漏洞处理完毕！")
    return 'get_comment'

def create_graph():
    """代码安全审计工作流主图"""
    repo_path = os.getenv("GITHUB_WORKSPACE", ".")
    retrieval_config = CodeRetrievalConfig(
        context_max_lines=int(os.getenv("RETRIEVAL_CONTEXT_MAX_LINES", "100")),
        single_line_max_length=500
    )
    
    # 实例化工具类
    retriever = CodeRetriever(repo_path, retrieval_config)
    analyzer = ProjectAnalyzer(repo_path, retrieval_config)
    knowledge_base = SecKnowledgeBase()
    
    general_tools = [*retriever.as_tools(), *analyzer.as_tools()]
    injection_knowledge = knowledge_base.create_vuln_query_tool('Injection_Expert')
    data_knowledge = knowledge_base.create_vuln_query_tool('Data_Asset_Expert')
    infra_knowledge = knowledge_base.create_vuln_query_tool('Infra_Supply_Expert')
    logic_knowledge = knowledge_base.create_vuln_query_tool('Logic_Identity_Expert')
    general_knowledge = knowledge_base.create_vuln_query_tool('General_Expert')
    bypass_knowledge = knowledge_base.create_bypass_query_tool()

    # 编译专家智能体子图
    injection_expert = InjectionExpert(additional_tools=[*general_tools, injection_knowledge, bypass_knowledge]).compile()
    data_asset_expert = DataAssetExpert(additional_tools=[*general_tools, data_knowledge]).compile()
    infra_supply_expert = InfraSupplyExpert(additional_tools=[*general_tools, infra_knowledge]).compile()
    logic_identity_expert = LogicIdentityExpert(additional_tools=[*general_tools, logic_knowledge]).compile()
    general_expert = GeneralExpert(additional_tools=[*general_tools, general_knowledge]).compile()
    
    # 组装主图
    workflow = StateGraph(AuditState)

    workflow.add_node('heuristic_scanner', heuristic_scanner_node)
    workflow.add_node('semantic_scanner', semantic_scanner_node)
    workflow.add_node('dynamic_router', dynamic_router_node)
    workflow.add_node('injection_expert', injection_expert)
    workflow.add_node('data_asset_expert', data_asset_expert)
    workflow.add_node('infra_supply_expert', infra_supply_expert)
    workflow.add_node('logic_identity_expert', logic_identity_expert)
    workflow.add_node('general_expert', general_expert)
    workflow.add_node('aggregate', aggregate_and_check_node)
    workflow.add_node('get_comment', get_comment_node)

    workflow.add_edge(START, 'heuristic_scanner')
    workflow.add_edge(START, 'semantic_scanner')
    workflow.add_edge('heuristic_scanner', 'dynamic_router')
    workflow.add_edge('semantic_scanner', 'dynamic_router')

    workflow.add_conditional_edges(
        'dynamic_router', 
        distribute_issues_edge, 
        ['injection_expert', 'data_asset_expert', 'infra_supply_expert', 
         'logic_identity_expert', 'general_expert']
    )

    workflow.add_edge('injection_expert', 'aggregate')
    workflow.add_edge('data_asset_expert', 'aggregate')
    workflow.add_edge('infra_supply_expert', 'aggregate')
    workflow.add_edge('logic_identity_expert', 'aggregate')
    workflow.add_edge('general_expert', 'aggregate')

    workflow.add_conditional_edges(
        'aggregate',
        check_rejection_edge,
        {
            'dynamic_router': 'dynamic_router',
            'get_comment': 'get_comment'
        }
    )

    workflow.add_edge('get_comment', END)

    return workflow.compile()

app = create_graph()