from langgraph.graph import StateGraph, START, END
from langgraph.types import Send
from langchain_core.runnables import RunnableConfig

from core.data_models import AgentState, AuditState
from nodes import heuristic_scanner_node, get_comments_node
from agents.expert_agents import SecretExpertAgent, InjectionExpertAgent


def distribute_issues(state: AuditState, config: RunnableConfig):
    """条件边路由：将扫描结果拆解，并分发给对应的 Agent 并行执行"""
    raw_reports = state.get("raw_reports", {})
    pr_diff = state.get("pr_diff", "")
    max_tool_turns = config['configurable'].get('agent_config').max_tool_turns
    sends = []
    
    for tool_name, issues in raw_reports.items():
        for issue in issues:
            agent_state_input = {
                "issue": issue, 
                "pr_diff": pr_diff,
                "remaining_tool_turns": max_tool_turns
            }

            # 路由到对应的专家智能体
            if tool_name == "gitleaks":
                sends.append(Send("secret_expert_agent", agent_state_input))
            elif tool_name == "semgrep" and "injection" in issue.get("cwe", "").lower():
                sends.append(Send("injection_expert_agent", agent_state_input))
                
    return sends

def create_graph():
    """代码安全审计工作流主图"""

    # 编译专家智能体子图
    secret_expert = SecretExpertAgent().compile()
    injection_expert = InjectionExpertAgent().compile()
    
    # 组装主图
    workflow = StateGraph(AgentState)

    workflow.add_node('heuristic_scanner', heuristic_scanner_node)
    workflow.add_node('get_comments', get_comments_node)
    workflow.add_node('secret_expert_agent', secret_expert)
    workflow.add_node('injection_expert_agent', injection_expert)

    workflow.add_edge(START, 'heuristic_scanner')
    workflow.add_conditional_edges('heuristic_scanner', distribute_issues, 
                                   ['secret_expert_agent', 'injection_expert_agent'])

    workflow.add_edge('secret_expert_agent', 'get_comments')
    workflow.add_edge('injection_expert_agent', 'get_comments')
    workflow.add_edge('get_comments', END)

    return workflow.compile()

app = create_graph()