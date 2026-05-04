from typing import List, Literal
from langgraph.graph import StateGraph, START, END
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
import functools
import logging

from core.data_models import AgentState
from core.config import LLMConfig


logger = logging.getLogger(__name__)


class ModelProvider:
    """带缓存的模型提供器，用来在接收RunnableConfig参数的同时，避免在节点中重复创建实例"""

    @functools.lru_cache(maxsize=10) # 将该函数的执行结果缓存，保存最多10组不同参数的执行结果
    @staticmethod
    def get_model_bound_tools(config: LLMConfig, tools: List, expert_name: str):
        # 相同的参数会返回缓存中的同一个对象
        model = ChatOpenAI(
            model=config.model_name,
            openai_api_base=config.base_url,
            openai_api_key=config.api_key,
            temperature=config.Role[expert_name].temperature,
            top_p=config.Role[expert_name].top_p,
            max_retries=3,
            seed=42
        )
        return model.bind_tools(tools)


class BaseExpertAgent():
    """专家智能体基类"""
    
    def __init__(self, expert_name: str, system_prompt: str, tools: List):
        self.expert_name = expert_name
        self.system_prompt = system_prompt
        self.tools = tools or []
        self.tools_by_name = {tool.name: tool for tool in self.tools}
        
    def _reasoning_node(self, state: AgentState, config: RunnableConfig):
        """核心推理节点：LLM 观察当前状态并决定下一步动作"""
        messages = state.get("messages", [])
        remaining_tool_turns = state.get('remaining_tool_turns')
        state_update_messages = []

        # 记录剩余工具调用轮次
        if remaining_tool_turns > 0:
            tool_sys_prompt = f"【系统提示】你还可以调用工具 {remaining_tool_turns} 轮。请合理规划，如果已有足够信心，可以直接给出最终的漏洞研判结果。"
        else:
            logger.warning(f"[{self.expert_name}] ⚠️ 工具调用轮次耗尽，强制要求大模型输出结论。")
            tool_sys_prompt = f"【系统提示】警告：你的工具调用轮次已全部用尽！你现在无法再查询知识库或调用工具。请立刻基于上述对话历史中的已知信息，给出最终研判结果。"

        # 如果是第一轮，初始化 System Prompt 和初始输入
        if not messages:
            logger.info(f"[{self.expert_name}] 🚀 开始全新漏洞研判: {state['issue'].get('id')}...")
            sys_msg = SystemMessage(
                content=self.system_prompt+"\n\n"+tool_sys_prompt
            )
            human_msg = HumanMessage(
                content=f"请对以下漏洞报告进行深度研判，你可以多次调用工具获取信息。\n"
                        f"【PR Diff】:\n{state['pr_diff']}\n\n"
                        f"【扫描报告】:\n{state['issue']}"
            )
            invocation_messages = [sys_msg, human_msg]
            state_update_messages = [human_msg]
        else:
            logger.info(f"[{self.expert_name}] 🧠 接收工具反馈，继续综合推理...")
            sys_msg = SystemMessage(content=tool_sys_prompt)
            invocation_messages = [sys_msg] + messages

        # 获取绑定了工具的 LLM 实例
        llm_config = config['configurable'].get('llm_config')
        model_with_tools = ModelProvider.get_model_bound_tools(
            config=llm_config,
            tools=self.tools,
            expert_name=self.expert_name
        )

        # 调用大模型
        response = model_with_tools.invoke(invocation_messages)
        state_update_messages.append(response)
        
        # 将 LLM 的回复（可能包含 tool_calls 或最终文字）加入状态
        return {"messages": state_update_messages}

    def _tools_call_node(self, state: AgentState, config: RunnableConfig):
        """动作执行节点：执行 LLM 要求的工具，并将结果返回"""
        tool_calls_message = state["messages"][-1] # 获取 LLM 的 tool_calls 消息
        remaining_tool_turns = state.get('remaining_tool_turns')
        tool_outputs = []

        if remaining_tool_turns <= 0:
            logger.warning(f"[{self.expert_name}] 🚫 拦截工具调用：次数已耗尽。")
            for tool_call in tool_calls_message.tool_calls:
                refusal_msg = "工具调用失败: 工具调用轮次已全部用尽，你必须立即输出最终的研判结果"
                tool_outputs.append(
                    ToolMessage(
                        content=refusal_msg, 
                        name=tool_call["name"], 
                        tool_call_id=tool_call["id"]
                    )
                )
            return {"messages": tool_outputs}

        # 遍历 LLM 发出的所有工具调用请求（可能同时调用多个）
        for tool_call in tool_calls_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_call_id = tool_call["id"]
            
            print(f"[{self.expert_name}] 🛠️ 正在执行工具: {tool_name}，参数: {tool_args}")
            
            # 找到对应的工具并执行
            if tool_name in self.tools_by_name:
                tool_instance = self.tools_by_name[tool_name]
                try:
                    result = tool_instance.invoke(tool_args)
                except Exception as e:
                    result = f"工具执行出错: {str(e)}"
            else:
                result = f"未找到名为 {tool_name} 的工具"
            
            tool_outputs.append(ToolMessage(
                                    content=str(result), 
                                    name=tool_name, 
                                    tool_call_id=tool_call_id
                                ))

        return {"messages": tool_outputs, "remaining_tool_turns": remaining_tool_turns - 1}

    def _format_output_node(self, state: AgentState, config: RunnableConfig):
        """格式化节点：提取 LLM 的最终研判结论"""
        print(f"[{self.expert_name}] ✅ 推理结束，格式化输出结果。\n")
        
        # 最后一条消息就是 LLM 最终文本回复
        final_answer = state["messages"][-1].content
        
        status = "True Positive" if "真实漏洞" in final_answer else "False Positive"
        
        final_result = {
            "id": state["issue"].get("id", "unknown"),
            "expert": self.expert_name,
            "status": status,
            "details": final_answer
        }
        
        return {"refined_results": [final_result]}        
    
    def _should_continue(self, state: AgentState) -> Literal["tools_call", "format_output"]:
        """条件边路由逻辑：判断是否需要调用工具"""
        last_message = state["messages"][-1]
        
        # 如果 LLM 在回答中包含了 tool_calls 属性，说明需要调用工具
        if last_message.tool_calls:
            return "tools_call"
        
        return "format_output"
        
    def compile(self):
        """构建并返回编译好的子图"""
        builder = StateGraph(AgentState)
        
        builder.add_node("reasoning", self._reasoning_node)
        builder.add_node("tools_call", self._tools_call_node)
        builder.add_node("format_output", self._format_output_node)
    
        builder.add_edge(START, "reasoning")
        builder.add_conditional_edges(
            "reasoning",
            self._should_continue,
            {
                "tools_call": "tools_call",
                "format_output": "format_output"
            }
        )
        builder.add_edge("tools_call", "reasoning")
        builder.add_edge("format_output", END)
        
        return builder.compile()


class DatabaseInjectionExpert(BaseExpertAgent):
    """负责数据库注入相关漏洞，例如 SQL 注入、NoSQL 注入、XPath 注入、LDAP 注入等"""
    def __init__(self):
        super().__init__(
            expert_name="Database_Injection_Expert"
        )


class BackEndInjectionExpert(BaseExpertAgent):
    """负责后端注入相关漏洞，如 OS 命令注入、代码注入、路径遍历、SSRF、反序列化、XXE等"""
    def __init__(self):
        super().__init__(

        )


class FrontEndInjectionExpert(BaseExpertAgent):
    """负责前端注入相关漏洞，如 XSS、SSTI、HTTP 响应头注入 (CRLF) """
    def __init__(self):
        super().__init__(

        )


class SecretExpert(BaseExpertAgent):
    """负责 Secrets 泄露：执行熵值与环境有效性研判"""
    def __init__(self):
        super().__init__(
            expert_name="Secret_Expert",
            system_prompt="你是一个高级安全专家，专门负责研判代码中硬编码的密钥、Token 和密码...",
            tools=["gitleaks_secrets_kb", "verify_token_validity_api"]
        )


class AccessControlExpert(BaseExpertAgent):
    """负责鉴权绕过/越权：执行逆向调用链与拦截器研判"""
    pass


class CryptographyExpert(BaseExpertAgent):
    """负责弱加密/哈希：执行算法标准与参数合规研判"""
    pass


class MemoryResourceExpert(BaseExpertAgent):
    """负责内存破坏/泄露：执行分支对称性与生命周期研判"""
    pass


class DependencyExpert(BaseExpertAgent):
    """负责 SCA 漏洞：执行跨库调用图寻址研判"""
    pass


class InfrastructureConfigExpert(BaseExpertAgent):
    """负责 IaC/配置：执行属性树与安全基线研判"""
    pass


class BusinessLogicExpert(BaseExpertAgent):
    """负责业务漏洞：执行逻辑契约与状态约束研判"""
    pass