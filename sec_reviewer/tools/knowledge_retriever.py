import logging
import frontmatter
from pathlib import Path
from typing import Annotated
from langchain_core.tools import StructuredTool
from langchain_core.tools.base import InjectedToolArg


logger = logging.getLogger(__name__)

KNOWLEDGE_ROOT_PATH = Path(__file__).parent.parent.resolve() / 'knowledge_base'


class VulnKnowledgeBase:
    """基于精确匹配的安全知识库"""
    
    def __init__(self):
        # 预加载所有文档，建立 漏洞名称/ID -> 绝对路径 的映射
        self.vuln_registry = {}
        self._build_registry()

    def _build_registry(self):
        """扫描目录，建立 专家领域 -> 漏洞名称 -> 路径 的映射字典"""
        for md_file in KNOWLEDGE_ROOT_PATH.rglob('*.md'):
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

    def create_expert_tool(self, expert_name: str) -> StructuredTool:
        """为特定专家生成专属的知识获取工具"""
        
        # 获取该专家领域下的所有已知漏洞类型
        expert_vulns = self.vuln_registry.get(expert_name, {})
        supported_vulns_list = list(expert_vulns.keys())
        supported_vulns_str = "\n".join([f"- {vuln}" for vuln in supported_vulns_list])

        def get_vulnerability_playbook(vuln_name: str) -> str:
            """
            获取目标漏洞的知识文档（包含机制、特征、误报样例、证实标准、证伪标准）。
            
            【何时使用】：
            1. [初始查询] 接收到扫描器报告后，研判开始前，如果【支持的漏洞列表】中包含要研判的漏洞类型，【必须】调用此工具获取该漏洞类型的知识文档。
            2. [类型纠正] 研判过程中，若发现代码的实际逻辑表明它其实是另一种存在于【支持的漏洞列表】中的漏洞，需再次调用该工具以获取正确漏洞类型的知识文档。

            【支持的漏洞列表】:
            {supported_vulns_str}
            
            Args:
                vuln_name (str): 必须是上述【支持的漏洞列表】中精确的漏洞名称。

            Returns:
                str: 目标漏洞的 Markdown 知识文档。
            """
            if vuln_name not in expert_vulns:
                return f"❌ 错误: 未找到名为 '{vuln_name}' 的漏洞知识。请确保您输入的名字在支持的列表中。"
            
            file_path = expert_vulns[vuln_name]
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = frontmatter.load(f).content
                return (
                    f"### 📚 漏洞研判知识库: {vuln_name}\n"
                    f"---\n\n"
                    f"{content.strip()}"
                )
            except Exception as e:
                return f"❌ 读取文档失败: {str(e)}"

        # 动态将支持的漏洞列表格式化进 docstring
        get_vulnerability_playbook.__doc__ = get_vulnerability_playbook.__doc__.format(
            supported_vulns_str=supported_vulns_str
        )

        return StructuredTool.from_function(
            func=get_vulnerability_playbook,
            name="get_vulnerability_playbook"
        )