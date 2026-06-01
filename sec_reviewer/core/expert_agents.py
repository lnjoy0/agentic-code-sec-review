import logging
import re
import uuid
import json
from typing import List, Literal
from langgraph.graph import StateGraph, START, END
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from pydantic import ValidationError

from sec_reviewer.knowledge_base.sys_prompts import (
    INJECTION_EXPERT_PROMPT, DATA_ASSET_EXPERT_PROMPT, INFRA_SUPPLY_EXPERT_PROMPT,
    LOGIC_IDENTITY_EXPERT_PROMPT, GENERAL_EXPERT_PROMPT
)
from .data_models import AgentState, ExpertAuditResult, Rejection, IssueAuditResult
from .config import LLMConfig



logger = logging.getLogger(__name__)


class AgentError(Exception):
    """Exception raised when agent working."""
    pass


class BaseExpertAgent():
    """专家智能体基类"""
    
    def __init__(self, expert_name: str, system_prompt: str, tools: List):
        self.expert_name = expert_name
        self.system_prompt = system_prompt
        self.tools = tools or []
        self.tools_by_name = {tool.name: tool for tool in self.tools 
                              if tool not in (ExpertAuditResult, Rejection)}
        
    def _get_model_bound_tools(self, config: LLMConfig, tools: List, expert_name: str):
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

    async def _reasoning_node(self, state: AgentState, config: RunnableConfig):
        """核心推理节点：LLM 观察当前状态并决定下一步动作"""
        messages = state.get("messages", [])
        remaining_turns = state.get('remaining_turns')
        rejection_history = state.get('rejection_history', {})
        issue = state["issue"]
        state_update_messages = []

        # 记录剩余行动轮数
        if remaining_turns > 0:
            remaining_turns_prompt = f"【系统提示】你还可以行动 {remaining_turns} 轮。请合理规划，如果已有足够信心，可以直接调用 ExpertAuditResult 工具，填入最终的漏洞研判结果。"
        else:
            logger.warning(
                f"[{self.expert_name}]-[issue({state['issue'].id})] ⚠️ 行动轮数耗尽，强制要求大模型输出结论。",
                f"\nLLM 行动记录：{str(messages)}"                
            )
            remaining_turns_prompt = f"【系统提示】警告：你的行动轮数已全部用尽！无法再调用除了 ExpertAuditResult 以外的其他工具。请立刻基于上述对话历史中的已知信息，调用 ExpertAuditResult 给出最终研判结果。"

        sys_msg = SystemMessage(content=self.system_prompt+"\n\n"+remaining_turns_prompt)

        # 如果是第一轮，初始化 System Prompt 和初始输入
        if not messages:
            logger.info(f"[{self.expert_name}] 🚀 开始全新漏洞研判: {issue.id} ({issue.name or issue.cwe})...")
            
            issue_json = issue.model_dump_json(indent=2)
            human_content = f"请对以下漏洞报告进行深度研判，你可以多轮调用工具获取信息。\n【扫描报告】：\n{issue_json}"
            if issue.id in rejection_history:
                rejection_reason = "\n【退回历史】该漏洞之前已被以下专家退回过，可以参考其退回原因，从中获取你需要的信息："
                for record in rejection_history[issue.id]:
                    rejection_reason += f"\n- 专家 [{record['expert']}]: {record['reason']}"
                human_content += rejection_reason
            human_msg = HumanMessage(content=human_content)

            invocation_messages = [sys_msg, human_msg]
            state_update_messages = [human_msg]
        else:
            logger.info(f"[{self.expert_name}]-[issue({state['issue'].id})] 🧠 接收工具反馈，继续综合推理...")
            invocation_messages = [sys_msg] + messages

        # 获取绑定了工具的 LLM 实例
        llm_config = config['configurable'].get('llm_config')
        model_with_tools = self._get_model_bound_tools(
            config=llm_config,
            tools=self.tools,
            expert_name=self.expert_name
        )

        # 调用大模型
        try:
            response = await model_with_tools.ainvoke(invocation_messages)
        except Exception as e:
            logger.error(f"LLM 调用出错：{e}。输入消息：{invocation_messages}")
            raise

        # 拦截并手动解析 vLLM 没能识别的自定义 XML 格式
        if not response.tool_calls and response.content and "<tool_call>" in response.content:
            logger.info(f"[{self.expert_name}]-[issue({state['issue'].id})] 检测到未解析的 XML Tool Call，开始手动提取...")
            
            parsed_tool_calls = []
            seen_calls = set() # 工具调用去重

            # 正则匹配 function name
            function_blocks = re.finditer(r"<function=([^>]+)>(.*?)</function>", response.content, re.DOTALL)
            for block in function_blocks:
                func_name = block.group(1).strip()
                func_body = block.group(2)
                args = {}
                
                # 正则匹配 parameters
                param_matches = re.finditer(r"<parameter=([^>]+)>(.*?)</parameter>", func_body, re.DOTALL)
                for p in param_matches:
                    param_name = p.group(1).strip()
                    param_value = p.group(2).strip()
                    
                    # 将类似字典或列表的结构尝试 JSON 解析
                    if (param_value.startswith('{') and param_value.endswith('}')) or \
                       (param_value.startswith('[') and param_value.endswith(']')):
                        try:
                            param_value = json.loads(param_value)
                        except json.JSONDecodeError:
                            logger.debug(f"[{self.expert_name}]-[issue({state['issue'].id})] 工具 {param_name} 的参数 JSON 解析失败，保持普通字符串: {param_value}")
                    
                    args[param_name] = param_value

                # 过滤重复的工具调用请求
                call_signature = f"{func_name}_{json.dumps(args, sort_keys=True)}"
                if call_signature in seen_calls:
                    logger.debug(f"[{self.expert_name}]-[issue({state['issue'].id})] 忽略同一轮次内重复的 Tool Call: {call_signature}")
                    continue
                seen_calls.add(call_signature)

                parsed_tool_calls.append({
                    "name": func_name,
                    "args": args,
                    "id": f"call_{uuid.uuid4().hex[:8]}"
                })
                logger.info(f"[{self.expert_name}]-[issue({state['issue'].id})] 成功解析 Tool Call: {func_name}, 参数: {args}")

            # 将解析到的工具列表注入回 response，并替换掉 content 中的原始 XML 文本
            if parsed_tool_calls:
                response.tool_calls = parsed_tool_calls
                response.content = "I have invoked the necessary tools to continue my analysis."
            
        # 将 LLM 的回复加入状态
        state_update_messages.append(response)
        return {"messages": state_update_messages}

    async def _tools_call_node(self, state: AgentState, config: RunnableConfig):
        """动作执行节点：执行 LLM 要求的工具，并将结果返回"""
        tool_calls_message = state["messages"][-1] # 获取 LLM 的 tool_calls 消息
        remaining_turns = state.get('remaining_turns')
        tool_outputs = []
        new_docs = [] # 用于接收新查询到的文档名称

        if remaining_turns <= -3:
            logger.error(
                f"[{self.expert_name}]-[issue({state['issue'].id})] 🚫 LLM 在行动轮数耗尽后仍然连续三轮没有调用 ExpertAuditResult 输出最终结果",
                f"\nLLM 行动记录：{str(state['messages'])}"
            )
            raise AgentError(f"{self.expert_name}故障，行动轮数耗尽，且 LLM 仍然连续三轮没有输出结果")
        elif remaining_turns <= 0:
            logger.warning(f"[{self.expert_name}]-[issue({state['issue'].id})] 🚫 拦截工具调用：行动轮数已耗尽。")
            for tool_call in tool_calls_message.tool_calls:
                refusal_msg = "工具调用失败: 行动轮数已全部用尽，你当前只能调用 ExpertAuditResult 工具"
                tool_outputs.append(
                    ToolMessage(
                        content=refusal_msg, 
                        name=tool_call["name"], 
                        tool_call_id=tool_call["id"]
                    )
                )
            return {"messages": tool_outputs, "remaining_turns": remaining_turns - 1}

        # 遍历 LLM 发出的所有工具调用请求（可能同时调用多个）
        for tool_call in tool_calls_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_call_id = tool_call["id"]
            
            print(f"[{self.expert_name}]-[issue({state['issue'].id})] 🛠️ 正在执行工具: {tool_name}，参数: {tool_args}")
            
            # 找到对应的工具并执行
            if tool_name in self.tools_by_name:
                tool_instance = self.tools_by_name[tool_name]

                try:
                    # 拦截 knowledge_retrieval 工具，处理去重与状态更新
                    if tool_name == "knowledge_retrieval":
                        vuln_name = tool_args.get("vuln_name")
                        viewed_docs = state.get("viewed_docs", [])
                        
                        if vuln_name in viewed_docs:
                            result = f"📄 您已经查阅过 '{vuln_name}' 的文档，它已在您的上下文中。"
                        else:
                            result = await tool_instance.ainvoke(tool_args, config=config)
                            if not result.startswith("❌"):
                                new_docs.append(vuln_name)
                    else:
                        # 其他正常工具直接调用
                        result = await tool_instance.ainvoke(tool_args, config=config)
                        
                except Exception as e:
                    result = f"工具执行出错: {str(e)}"
            else:
                result = f"未找到名为 {tool_name} 的工具"
            
            tool_outputs.append(ToolMessage(
                                    content=str(result), 
                                    name=tool_name, 
                                    tool_call_id=tool_call_id
                                ))

        return {
            "messages": tool_outputs, 
            "remaining_turns": remaining_turns - 1,
            "viewed_docs": new_docs
        }

    def _format_output_node(self, state: AgentState):
        """格式化节点：提取 LLM 的最终研判结论并进行 Pydantic 强校验"""
        logger.info(f"[{self.expert_name}]-[issue({state['issue'].id})] ⚖️ 准备校验并格式化输出结果...")
        last_message = state["messages"][-1]
        issue = state['issue']
        
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "ExpertAuditResult":
                raw_args = tool_call["args"] # 获取 ExpertAuditResult 的参数
                
                try:
                    # 实例化 Pydantic 模型，如果数据校验不通过会抛出异常
                    audit_obj = ExpertAuditResult(**raw_args) 

                    audit_data = audit_obj.model_dump() 

                    audit_result = IssueAuditResult(
                        id=issue.id,
                        expert=self.expert_name,
                        path=issue.path,
                        start_line=issue.snippet_region.start_line,
                        end_line=issue.snippet_region.end_line,
                        details=audit_data
                    )

                    logger.info(f"[{self.expert_name}]-[issue({state['issue'].id})] ✅ 结果校验通过，研判完成。")
                    return {"audit_results": [audit_result]}

                except ValidationError as e:
                    error_str = str(e)
                    logger.warning(f"[{self.expert_name}]-[issue({state['issue'].id})] ❌ ExpertAuditResult 数据校验失败，打回重做: \n{error_str}")

                    # 构造一个 ToolMessage，将报错扔回给大模型
                    error_msg = ToolMessage(
                        content=f"【提交失败】你提交的最终结论未通过逻辑校验，请根据以下报错修正后重新调用 ExpertAuditResult:\n{error_str}",
                        name=tool_call["name"],
                        tool_call_id=tool_call["id"]
                    )
                    return {"messages": [error_msg]}    

    def _retry_node(self, state: AgentState):
        """
        当模型输出纯文本而没有调用工具时，触发此节点进行警告。
        """
        remaining_turns = state.get('remaining_turns')

        if remaining_turns <= -3:
            logger.error(f"[{self.expert_name}]-[issue({state['issue'].id})] ⚠️ LLM 在行动轮数耗尽后仍然连续三轮没有调用 ExpertAuditResult 输出最终结果")
            raise AgentError(f"{self.expert_name}故障，行动轮数耗尽，且 LLM 仍然连续三轮没有输出结果")
        elif remaining_turns <= 0:
            logger.warning(f"[{self.expert_name}]-[issue({state['issue'].id})] ⚠️ 行动轮数已耗尽。")
            warning_content = "行动轮数已全部用尽，你当前只能调用 ExpertAuditResult 工具"
        else:
            logger.warning(f"[{self.expert_name}]-[issue({state['issue'].id})] ⚠️ 检测到 LLM 仅输出了纯文本内容，进行警告\nLLM 输出内容：{state['messages'][-1]}")
            # 构造一条警告消息
            warning_content = (
                "【系统拦截】你只能进行工具调用，禁止输出纯文本内容。\n"
                "请调用 `ExpertAuditResult` 工具来提交最终的研判结果，或者调用其他工具来辅助研判分析。"
            )
        
        warning_msg = HumanMessage(content=warning_content)
    
        return {"messages": [warning_msg], "remaining_turns": remaining_turns - 1}

    def _reject_node(self, state: AgentState):
        """当该专家认为分配的漏洞不在它的职能范围时，触发该节点进行退回"""
        last_message = state["messages"][-1]
        issue_id = state["issue"].id
        
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "Rejection":
                raw_args = tool_call["args"]

                try:
                    reject_obj = Rejection(**raw_args) 
                    reject_reason = reject_obj.model_dump()['reject_reason']

                    record = {
                        "expert": self.expert_name,
                        "reason": reject_reason
                    }

                    logger.warning(f"[{self.expert_name}] ↩️ 拒绝处理漏洞 {state['issue'].id} ({state['issue'].name or state['issue'].cwe})，将其退回给Router。理由：{reject_reason}")
                    return {"rejection_history": {issue_id: [record]}}

                except ValidationError as e:
                    logger.warning(f"[{self.expert_name}]-[issue({state['issue'].id})] ❌ Rejection 数据校验失败，打回重做: \n{str(e)}")
                    
                    error_msg = ToolMessage(
                        content=f"【退回漏洞失败】必须填写拒绝原因。",
                        name=tool_call["name"],
                        tool_call_id=tool_call["id"]
                    )
                    return {"messages": [error_msg]}

    def _router_edge(self, state: AgentState) -> Literal["reject", "retry", "tools_call", "format_output"]:
        """条件边路由逻辑：判断是否需要调用工具"""
        last_message = state["messages"][-1]
        
        # 如果没有调用任何工具，路由到 retry 节点
        if not last_message.tool_calls:
            return "retry" 
            
        tool_name = last_message.tool_calls[0]["name"]
        
        if tool_name == "ExpertAuditResult":
            return "format_output"
        elif tool_name == "Rejection":
            return "reject"
        else:
            return "tools_call"

    def _data_validation_router_edge(self, state: AgentState) -> Literal["reasoning", "__end__"]:
        """在 Pydantic 数据校验之后，判断是否校验成功，如果校验失败则需要路由回 LLM"""
        last_message = state["messages"][-1]
        
        # 如果最后一条消息是 ToolMessage，则说明校验没有通过
        if isinstance(last_message, ToolMessage):
            return "reasoning"
            
        return END

    def compile(self):
        """构建并返回编译好的子图"""
        builder = StateGraph(AgentState)
        
        builder.add_node("reasoning", self._reasoning_node)
        builder.add_node("tools_call", self._tools_call_node)
        builder.add_node("format_output", self._format_output_node)
        builder.add_node("retry", self._retry_node)
        builder.add_node("reject", self._reject_node)
    
        builder.add_edge(START, "reasoning")
        builder.add_conditional_edges(
            "reasoning",
            self._router_edge,
            {
                "reject": "reject",
                "retry": "retry",
                "tools_call": "tools_call",
                "format_output": "format_output"
            }
        )
        builder.add_edge("retry", "reasoning")
        builder.add_edge("tools_call", "reasoning")
        builder.add_conditional_edges(
            "reject",
            self._data_validation_router_edge,
            {
                "reasoning": "reasoning",
                END: END
            }
        )
        builder.add_conditional_edges(
            "format_output",
            self._data_validation_router_edge,
            {
                "reasoning": "reasoning",
                END: END
            }
        )
        
        return builder.compile()


class InjectionExpert(BaseExpertAgent):
    """负责SQL注入、OS命令注入、代码注入、XSS、SSRF、路径遍历、反序列化等各种注入"""
    def __init__(self, additional_tools: List = None):
        tools = [ExpertAuditResult, Rejection] + (additional_tools or [])
        super().__init__(
            expert_name="Injection_Expert",
            system_prompt=INJECTION_EXPERT_PROMPT,
            tools=tools
        )


class DataAssetExpert(BaseExpertAgent):
    """负责凭据泄露和密码学"""
    def __init__(self, additional_tools: List = None):
        tools = [ExpertAuditResult, Rejection] + (additional_tools or [])
        super().__init__(
            expert_name="Data_Asset_Expert",
            system_prompt=DATA_ASSET_EXPERT_PROMPT,
            tools=tools
        )


class InfraSupplyExpert(BaseExpertAgent):
    """负责依赖项与基础设施配置"""
    def __init__(self, additional_tools: List = None):
        tools = [ExpertAuditResult, Rejection] + (additional_tools or [])
        super().__init__(
            expert_name="Infra_Supply_Expert",
            system_prompt=INFRA_SUPPLY_EXPERT_PROMPT,
            tools=tools
        )

class LogicIdentityExpert(BaseExpertAgent):
    """负责访问控制和业务逻辑"""
    def __init__(self, additional_tools: List = None):
        tools = [ExpertAuditResult, Rejection] + (additional_tools or [])
        super().__init__(
            expert_name="Logic_Identity_Expert",
            system_prompt=LOGIC_IDENTITY_EXPERT_PROMPT,
            tools=tools
        )

class GeneralExpert(BaseExpertAgent):
    """负责无法清晰划分给其他专家的通用漏洞"""
    def __init__(self, additional_tools: List = None):
        tools = [ExpertAuditResult] + (additional_tools or [])
        super().__init__(
            expert_name="General_Expert",
            system_prompt=GENERAL_EXPERT_PROMPT,
            tools=tools
        )