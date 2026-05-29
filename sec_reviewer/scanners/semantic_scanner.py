from typing import List, Dict, Set, Tuple, Optional
from unidiff import PatchedFile
from pathlib import Path
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableSerializable
from langchain_openai import ChatOpenAI
import logging
import asyncio
import re

from sec_reviewer.core.config import ScannerConfig
from sec_reviewer.core.data_models import ScannedIssue, LLMScanReport, LLMScannedIssue, SnippetRegion
from sec_reviewer.tools.code_retriever import CodeRetriever
from sec_reviewer.tools.project_analyzer import ProjectAnalyzer
from sec_reviewer.knowledge_base.sys_prompts import SCANNER_PROMPT


logger = logging.getLogger(__name__)


class LLMSemanticScanner:
    """基于大语言模型的语义模式安全扫描器"""

    def __init__(self, scanner_config: ScannerConfig, llm_client: ChatOpenAI):
        self.scanner_config = scanner_config

        structured_llm = llm_client.with_structured_output(LLMScanReport)
        prompt = ChatPromptTemplate.from_messages([
            ("system", SCANNER_PROMPT),
            ("human", "请分析以下增量代码是否引入了漏洞:\n{full_context}")
        ])
        self.chain = prompt | structured_llm

    async def get_report(self, patched_files: List[PatchedFile]) -> Dict[str, List[ScannedIssue]]:
        """获取 LLM 语义分析的扫描报告"""
        logger.info("LLM Semantic Scanner running...")
        logger.info(f"LLM target files count: {len(patched_files)}")

        semaphore = asyncio.Semaphore(50) # 每个 hunk 的分析占用一个信号量
        
        tasks = [self._analyze_file(f, semaphore) for f in patched_files]
        results = await asyncio.gather(*tasks)

        all_issues = [issue for sublist in results for issue in sublist]
        
        logger.info(f"LLM Semantic Scanner found {len(all_issues)} potential issues")

        return {
            "llm": all_issues
        }

    async def _analyze_file(
        self, 
        patched_file: PatchedFile, 
        semaphore: asyncio.Semaphore
    ) -> List[ScannedIssue]:
        """调用 LLM 分析单个变更文件"""
        file_path = patched_file.path
        
        seen_scope = set()
        contexts = []
        # 遍历 diff 中的每一个变更代码块 (Hunk) 提取对应上下文
        for hunk in patched_file:
            start_line = hunk.target_start
            end_line = max(start_line, start_line + hunk.target_length - 1) 
            
            hunk_context, scope = await self._get_context(file_path, start_line, end_line)
            if hunk_context and scope not in seen_scope: # 去重
                seen_scope.add(scope)
                contexts.append(hunk_context)

        if not contexts:
            return []

        tasks = [
            self._analyze_hunk(hunk_context, file_path, self.chain, semaphore) 
            for hunk_context in contexts
        ]
        results = await asyncio.gather(*tasks)

        # 转为 ScannedIssue 对象
        scanned_issues = self._convert_to_scanned_issues(
            results, file_path, patched_file, hunk_context
        )

        if not scanned_issues:
            logger.info(f"文件 {file_path} 中未发现漏洞")
        else:
            logger.info(f"文件 {file_path} 中发现 {len(scanned_issues)} 个漏洞：{str([issue.name for issue in scanned_issues])}")

        return scanned_issues

    def _convert_to_scanned_issues(
        self, 
        results: list[tuple[LLMScanReport | None, str]], 
        file_path: str, 
        patched_file: PatchedFile,
        hunk_context: str
    ) -> list[ScannedIssue]:
        """
        验证行号，并且将 LLMScannedIssue 转换为 ScannedIssue 对象，添加文件路径和上下文
        """
        scanned_issues = []
        added_lines = self._get_added_lines(patched_file)
        
        for report, hunk_context in results:
            if not report or not report.issues:
                continue

            for issue in report.issues:
                issue_lines = set(range(issue.start_line, issue.end_line + 1))

                if issue_lines.intersection(added_lines): # 校验报告的漏洞行号是否与新增行号有交集
                    # 将上下文中的指针改到LLM返回的漏洞范围
                    context = self.modify_context_pointers(hunk_context, issue.start_line, issue.end_line)
                    
                    scanned_issues.append(ScannedIssue(
                        name=issue.name,
                        path=file_path,
                        message=issue.information,
                        severity=issue.severity,
                        confidence_score=issue.confidence_score,
                        snippet_region=SnippetRegion(
                            start_line=issue.start_line,
                            end_line=issue.end_line
                        ),
                        snippet_text=issue.vulnerable_code_snippet,
                        context=context
                    ))
                else:
                    logger.debug(
                        f"过滤掉文件 {file_path} 中的漏洞: {issue.name}。"
                        f"其行号 {issue.start_line}-{issue.end_line} 不在 PR 增量范围内。"
                    )

        return scanned_issues

    async def _analyze_hunk(
        self,
        hunk_context: str,
        file_path: str, # 相对路径
        chain: RunnableSerializable,
        semaphore: asyncio.Semaphore
    ) -> tuple[Optional[LLMScanReport], str]:
        """处理单个变更代码块的异步子任务"""
        async with semaphore:
            try:
                report = await chain.ainvoke({"full_context": hunk_context})
                return report, hunk_context
            except Exception as e:
                logger.error(f"文件 {file_path} 的 Hunk 分析或 Pydantic 结构校验失败：{e}")
                return None, hunk_context

    def _get_added_lines(self, patched_file: PatchedFile) -> Set[int]:
        """获取文件中新增的行号集合"""
        added_lines = set()
        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    added_lines.add(line.target_line_no)
        return added_lines

    async def _get_context(
        self, 
        file_path: str, 
        start_line: int, 
        end_line: int
    ) -> Tuple[str, Tuple]:
        """
        根据文件类型提取代码变更周边的上下文。
        结合基于 AST 的提取（Python）和基于滑动窗口的提取（非 Python）。
        """
        try:
            suffix = Path(file_path).suffix.lower()

            if suffix == '.py':
                retriever = CodeRetriever(self.scanner_config.workspace_dir)
                _, context, scope = await retriever.core_get_code_snippet_and_context(
                    file_path=file_path,
                    start_point=(start_line, 1),
                    end_point=(end_line, 1),
                    min_lines=10
                )
                return context, scope
            else:
                analyzer = ProjectAnalyzer(self.scanner_config.workspace_dir)
                context, scope = await analyzer.core_get_file_context(
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line
                )
                return context, scope

        except FileNotFoundError:
            logger.warning(f"提取上下文跳过：找不到文件 {file_path}")
            return "", ()
        except ValueError as ve:
            logger.warning(f"提取上下文跳过 (值域错误) {file_path}: {ve}")
            return "", ()
        except Exception as e:
            logger.error(f"提取 {file_path} 上下文时发生未知错误: {e}")
            return "", ()

    def modify_context_pointers(
        self,
        context_str: str, 
        new_start_line: int, 
        new_end_line: int
    ) -> str:
        """
        修改提取出的上下文文本中的 => 指针位置，并同步更新标题行号。
        """
        if new_start_line > new_end_line:
            raise ValueError(f"❌ 错误: 新的起始行号 ({new_start_line}) 不能大于结束行号 ({new_end_line})。")

        lines = context_str.split("\n")
        updated_lines = []
        
        # 匹配头部标题: "### 🎯 上下文提取: `...` (Line X-Y)"
        header_pattern = re.compile(r'(\(Line )\d+-\d+(\))')
        
        # 匹配代码行: 匹配前缀（"=>" 或 "  "），加一个空格，加行号(4位数字)，加 " | " 和代码内容
        line_pattern = re.compile(r'^(=>|  ) (\s*\d+)( \| )(.*)$')

        for line in lines:
            # 替换头部标题
            if line.startswith("### 🎯 上下文提取:"):
                line = header_pattern.sub(rf'\g<1>{new_start_line}-{new_end_line}\g<2>', line)
                updated_lines.append(line)
                continue
            
            # 替换正文行
            match = line_pattern.match(line)
            if match:
                current_line_num = int(match.group(2).strip())
                
                if new_start_line <= current_line_num <= new_end_line:
                    new_prefix = "=>"
                else:
                    new_prefix = "  "
                    
                updated_line = f"{new_prefix} {match.group(2)}{match.group(3)}{match.group(4)}"
                updated_lines.append(updated_line)
            else:
                updated_lines.append(line)
                
        return "\n".join(updated_lines)