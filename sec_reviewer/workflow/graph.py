from langgraph.graph import StateGraph, START, END
from langgraph.types import Send
from typing import Literal
import logging
import os

from tools.code_retriever import CodeRetriever
from tools.project_analyzer import ProjectAnalyzer
from tools.knowledge_retriever import VulnKnowledgeBase
from core.data_models import AgentState, AuditState
from core.expert_agents import (InjectionExpert, DataAssetExpert, InfraSupplyExpert,
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
    scanner_reports = state.get("scanner_reports", {})
    audit_results = state.get("audit_results", [])
    
    # 总漏洞数
    total_issues = sum([len(issues) for issues in scanner_reports.values()])
    
    # 已经拿到最终研判结果的漏洞数
    finished_issues = len(audit_results)
    
    if finished_issues < total_issues:
        logger.info(f"🔄 检测到退回！进度 {finished_issues}/{total_issues}。重定向回 Router...")
        return "dynamic_router"
    
    logger.info("✅ 所有漏洞处理完毕！")
    return 'get_comment'

def create_graph():
    """代码安全审计工作流主图"""
    repo_path = os.getenv("GITHUB_WORKSPACE", ".")

    # 实例化工具类
    code_retriever = CodeRetriever(repo_path)
    analyzer = ProjectAnalyzer(repo_path)
    knowledge_base = VulnKnowledgeBase()
    
    general_tools = [*code_retriever.as_tools(), *analyzer.as_tools()]
    injection_knowledge = knowledge_base.create_expert_tool('Injection_Expert')
    data_knowledge = knowledge_base.create_expert_tool('Data_Asset_Expert')
    infra_knowledge = knowledge_base.create_expert_tool('Infra_Supply_Expert')
    logic_knowledge = knowledge_base.create_expert_tool('Logic_Identity_Expert')
    general_knowledge = knowledge_base.create_expert_tool('General_Expert')

    # 编译专家智能体子图
    injection_expert = InjectionExpert(additional_tools=[*general_tools, injection_knowledge]).compile()
    data_asset_expert = DataAssetExpert(additional_tools=[*general_tools, data_knowledge]).compile()
    infra_supply_expert = InfraSupplyExpert(additional_tools=[*general_tools, infra_knowledge]).compile()
    logic_identity_expert = LogicIdentityExpert(additional_tools=[*general_tools, logic_knowledge]).compile()
    general_expert = GeneralExpert(additional_tools=[*general_tools, general_knowledge]).compile()
    
    # 组装主图
    workflow = StateGraph(AgentState)

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