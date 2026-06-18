import logging
import frontmatter
import asyncio
import aiofiles
from pathlib import Path
from langchain_core.tools import StructuredTool
from typing import Optional


logger = logging.getLogger(__name__)

VULN_BASE_ROOT_PATH = Path(__file__).parent.parent.resolve() / 'knowledge_base' / 'vulnerability_database'
BYPASS_TEC_ROOT_PATH = Path(__file__).parent.parent.resolve() / 'knowledge_base' / 'bypass_techniques'

class SecKnowledgeBase:
    """基于精确匹配的安全知识库"""
    
    def __init__(self):
        self.vuln_registry = {}
        self.bypass_registry = {}
        self._build_registry()

    def _build_registry(self):
        """扫描目录，建立文档映射字典"""

        # 建立 专家领域 -> 漏洞名称 -> 路径 的映射字典
        for md_file in VULN_BASE_ROOT_PATH.rglob('*.md'):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    parsed_file = frontmatter.load(f)
                
                metadata = parsed_file.metadata
                doc_name = metadata.get('name', md_file.stem)
                domains = metadata.get('domain', ["General_Expert"])

                if isinstance(domains, str):
                    domains = [domains]

                for domain in domains:
                    if domain not in self.vuln_registry:
                        self.vuln_registry[domain] = {}
                    self.vuln_registry[domain][doc_name] = md_file
            
            except Exception as e:
                logger.error(f"加载文档失败 {md_file}: {e}")
        
        # 建立 绕过技巧文档 -> 路径 的映射字典
        for md_file in BYPASS_TEC_ROOT_PATH.rglob('*.md'):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    parsed_file = frontmatter.load(f)
                
                metadata = parsed_file.metadata
                doc_name = metadata.get('name', md_file.stem)

                self.bypass_registry[doc_name] = md_file
            except Exception as e:
                logger.error(f"加载文档失败 {md_file}: {e}")

    def create_vuln_query_tool(self, expert_name: str) -> StructuredTool:
        """为特定专家生成专属的知识获取工具"""
        
        # 获取该专家领域下的所有已知漏洞类型
        expert_vulns = self.vuln_registry.get(expert_name, {})
        supported_vulns_list = list(expert_vulns.keys())
        supported_vulns_str = "\n".join([f"- {vuln}" for vuln in supported_vulns_list])

        async def get_vulnerability_playbook(vuln_name: str) -> str:
            """
            获取目标漏洞的知识文档（包含机制、特征、误报样例、证实标准、证伪标准）。
            
            【何时使用】：
            1. [初始查询] 接收到扫描器报告后，研判开始前，如果【支持的漏洞列表】中包含要研判的漏洞类型，【必须】调用此工具获取该漏洞类型的知识文档。
            2. [类型纠正] 研判过程中，若发现代码的实际逻辑表明它其实是另一种存在于【支持的漏洞列表】中的漏洞，需再次调用该工具以获取正确漏洞类型的知识文档。

            【支持的漏洞列表】:
            {supported_vulns_str}
            
            Args:
                vuln_name (str): 必须是上述【支持的漏洞列表】中精确的漏洞名称。

            Rerounds:
                str: 目标漏洞的 Markdown 知识文档。
            """
            if vuln_name not in expert_vulns:
                return f"❌ 错误: 未找到名为 '{vuln_name}' 的漏洞知识。请确保您输入的名字在支持的列表中。"
            
            file_path = expert_vulns[vuln_name]
            try:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                        raw_text = await f.read()
                    
                    content = frontmatter.loads(raw_text).content
                except FileNotFoundError:
                    logger.error(f"查询漏洞 {vuln_name} 知识文档失败，文件 `{file_path}` 不存在")
                    return f"❌ 错误: 文件不存在 `{file_path}`"
                
                return (
                    f"### 📚 漏洞研判知识库: {vuln_name}\n"
                    f"---\n\n"
                    f"{content.strip()}"
                )
            except Exception as e:
                logger.error(f"读取文档失败：{str(e)}")
                return f"❌ 读取文档失败: {str(e)}"

        # 动态将支持的漏洞列表格式化进 docstring
        get_vulnerability_playbook.__doc__ = get_vulnerability_playbook.__doc__.format(
            supported_vulns_str=supported_vulns_str
        )

        return StructuredTool.from_function(coroutine=get_vulnerability_playbook, name="get_vulnerability_playbook")

    def create_bypass_query_tool(self) -> str:
        supported_bypass_tec_list = list(self.bypass_registry.keys())
        supported_bypass_tec_str = "\n".join([f"- {tec}" for tec in supported_bypass_tec_list])

        async def get_bypass_techniques(name: str) -> str:
            """
            获取目标高级绕过技巧的知识文档。
            
            【何时使用】：
            1. [数据流审计与防御评估] 当追踪数据流发现用户可控输入经过了开发者的清洗、过滤、转义或正则校验逻辑时。可以调用此工具以辅助评估该代码级防御逻辑是否严密，以及是否存在被特定手法绕过的可能性。

            【专家研判警示】：
            - ⚠️ 本文档收录的仅为部分典型的绕过技巧，**并未穷尽所有绕过可能**。
            - ⚠️ 即使该文档中的所有方法都无法绕过当前的过滤逻辑，也**绝不等于**该防御绝对安全。请务必结合具体的代码上下文、语言特性或框架机制，运用您的代码审计专家经验进行最终判定。

            【支持的绕过技巧列表】:
            {supported_bypass_tec_str}
            
            Args:
                name (str): 必须是上述【支持的绕过技巧列表】中精确的文档名称。

            Returns:
                str: 高级绕过技巧的 Markdown 知识文档。
            """
            if name not in self.bypass_registry:
                return f"❌ 错误: 未找到名为 '{name}' 的文档。请确保您输入的名字在支持的列表中。"
            
            file_path = self.bypass_registry[name]
            try:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                        raw_text = await f.read()
                    
                    content = frontmatter.loads(raw_text).content
                except FileNotFoundError:
                    logger.error(f"查询绕过技巧 {name} 失败，文件 `{file_path}` 不存在")
                    return f"❌ 错误: 文件不存在 `{file_path}`"
                
                return (
                    f"### 📚 高级绕过技巧: {name}\n"
                    f"---\n\n"
                    f"{content.strip()}"
                )
            except Exception as e:
                logger.error(f"读取文档失败：{str(e)}")
                return f"❌ 读取文档失败: {str(e)}"

        get_bypass_techniques.__doc__ = get_bypass_techniques.__doc__.format(
            supported_vulns_str=supported_bypass_tec_str
        )

        return StructuredTool.from_function(coroutine=get_bypass_techniques, name="get_bypass_techniques")