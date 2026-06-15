from typing import List, Dict, Set, Tuple, Optional, Any
from unidiff import PatchedFile
from pathlib import Path
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableSerializable
import logging
import asyncio

from sec_reviewer.core.config import ScannerConfig, CodeRetrievalConfig
from sec_reviewer.core.data_models import ScannedIssue, SnippetRegion, LLMScanReport
from sec_reviewer.core.expert_agents import save_request_messages
from sec_reviewer.tools.code_retriever import CodeRetriever
from sec_reviewer.tools.project_analyzer import ProjectAnalyzer
from sec_reviewer.knowledge_base.sys_prompts import SCANNER_PROMPT


logger = logging.getLogger(__name__)


class LLMSemanticScanner:
    """基于大语言模型的语义模式安全扫描器"""

    def __init__(
        self, 
        scanner_config: ScannerConfig, 
        retrieval_config: CodeRetrievalConfig, 
        structured_llm: Any
    ):
        self.config = scanner_config
        self.retriever = CodeRetriever(self.config.workspace_dir, retrieval_config)
        self.analyzer = ProjectAnalyzer(self.config.workspace_dir, retrieval_config)

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", SCANNER_PROMPT),
            ("human", "请分析以下增量代码是否引入了漏洞:\n{full_context}")
        ])
        self.chain = self.prompt | structured_llm

    async def get_report(self, patched_files: List[PatchedFile]) -> Dict[str, List[ScannedIssue]]:
        """获取 LLM 语义分析的扫描报告"""
        logger.info("LLM Semantic Scanner running...")
        logger.info(f"LLM target files count: {len(patched_files)}")

        semaphore = asyncio.Semaphore(25)
        
        tasks = [self._analyze_file(f, semaphore) for f in patched_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"某个文件分析时发生了未捕获的严重异常: {res}")
                continue
            valid_results.append(res)

        all_issues = [issue for sublist in valid_results for issue in sublist]
        
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

        # 设置 LLM 每次处理的代码上下文最大行数
        context_max_lines = self.config.context_max_lines
        # 设置上下文切分阈值，超过最大行数的 25% 才触发切分，保证不会有切分后的分块过于小
        massive_hunk_threshold = int(context_max_lines * 1.25)

        # 遍历 diff 中的每一个变更代码块 (Hunk)
        for hunk in patched_file:
            # 取每个 Hunk 中的最小和最大新增行之间的区间，作为目标代码片段，提取其上下文
            added_lines = [
                line.target_line_no for line in hunk # 1-indexed
                if getattr(line, 'is_added', False)
            ]
            if not added_lines: # 如果这个 hunk 没有新增行，则跳过
                continue

            start_line = min(added_lines)
            end_line = max(added_lines)

            # 如果目标区间太大，则执行切分
            if (end_line - start_line) > massive_hunk_threshold:
                sub_intervals = await self._split_massive_hunk(file_path, start_line, end_line, context_max_lines)
            else:
                sub_intervals = [(start_line, end_line)]
            
            # 遍历产生的所有分析区间
            for sub_start, sub_end in sub_intervals:
                hunk_context, scope = await self._get_context(file_path, sub_start, sub_end)
                if hunk_context and scope not in seen_scope: # 去重
                    seen_scope.add(scope)
                    contexts.append(hunk_context)

        logger.info(f"文件 {file_path} 生成了 {len(contexts)} 个分析上下文，准备调用 LLM 进行扫描。上下文区间包括: {seen_scope}")

        if not contexts:
            return []

        tasks = [
            self._analyze_hunk(hunk_context, file_path, self.chain, semaphore, i) 
            for i, hunk_context in enumerate(contexts)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = []
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"文件 {file_path} 中，某个 Hunk 分析时发生了未捕获的严重异常: {res}")
                continue
            valid_results.append(res)

        # 转为 ScannedIssue 对象
        scanned_issues = await self._convert_to_scanned_issues(
            valid_results, file_path, patched_file
        )

        if not scanned_issues:
            logger.info(f"文件 {file_path} 中未发现漏洞")
        else:
            logger.info(f"文件 {file_path} 中发现 {len(scanned_issues)} 个漏洞：{str([issue.name for issue in scanned_issues])}")

        return scanned_issues

    async def _analyze_hunk(
        self,
        hunk_context: str,
        file_path: str, # 相对路径
        chain: RunnableSerializable,
        semaphore: asyncio.Semaphore,
        index: int
    ) -> tuple[Optional[LLMScanReport], str, Optional[Any]]:
        """处理单个变更代码块的异步子任务"""
        async with semaphore:
            inputs = {"full_context": hunk_context}
            async def _save_msg():
                try:
                    prompt_value = await self.prompt.ainvoke(inputs)
                    raw_messages = prompt_value.to_messages()
                    name = f"file({file_path.split('.')[0].replace('/','_')})_scan_{index}"
                    await save_request_messages(raw_messages, 'scanner', name)
                except Exception as e:
                    logger.warning(f"⚠️ 保存 file({file_path.split('.')[0]})_scan_{index} 请求消息时发生错误: {e}")

            save_task = asyncio.create_task(_save_msg()) # 放入事件循环后台执行，不阻塞 LLM 调用

            try:
                result = await chain.ainvoke(inputs)
                
                tool_name = result.tool_calls[0]['name']
                tool_args = result.tool_calls[0]['args']

                if tool_name != "LLMScanReport":
                    logger.error(f"文件 {file_path} 的代码块分析失败，LLM 的输出未调用 LLMScanReport 工具")
                    return None, hunk_context, None
                
                report = LLMScanReport(**tool_args)

                return report, hunk_context, result
            except Exception as e:
                logger.error(f"文件 {file_path} 的代码块分析或 Pydantic 结构校验失败：{e}")
                logger.exception("error: ")
                return None, hunk_context, None
            finally:
                await save_task # 确保报错时也保存请求消息

    async def _split_massive_hunk(
        self, 
        file_path: str, 
        start_line: int, # 1-indexed
        end_line: int, 
        max_lines: int = 500
    ) -> List[Tuple[int, int]]:
        """
        将超大的代码区间，按语义（类/函数）切分成合适大小的多个区间
        """
        # 获取与指定行数范围有交集的所有类/函数的起止行号
        def_scopes = await self.retriever.get_def_scopes(file_path, start_line, end_line)

        # 如果没有拿到按定义拆分的起止行号，则按行数强行切分
        if not def_scopes:
            return self._fallback_line_split(start_line, end_line, max_lines)

        chunks = []
        current_chunk_start = None
        current_chunk_end = None

        for node in def_scopes:
            node_start = node['start']
            node_end = node['end']

            if current_chunk_start is None:
                # 开启新块
                current_chunk_start = node_start
                current_chunk_end = node_end
            else:
                # 判断加入当前节点之后，会不会超过最大行数
                if (node_end - current_chunk_start + 1) <= max_lines:
                    # 不超过，融合进当前块，更新 end
                    current_chunk_end = node_end
                else:
                    # 超过了，把旧块保存起来
                    chunks.append((current_chunk_start, current_chunk_end))
                    # 当前节点作为新块的开始
                    current_chunk_start = node_start
                    current_chunk_end = node_end

        # 将最后一个块保存下来
        if current_chunk_start is not None:
            chunks.append((current_chunk_start, current_chunk_end))

        return chunks

    def _fallback_line_split(self, start_line: int, end_line: int, max_lines: int) -> List[Tuple[int, int]]:
        """兜底方案：如果 AST 解析失败，直接按固定行数死板切分"""
        return [
            (i, min(i + max_lines - 1, end_line))
            for i in range(start_line, end_line + 1, max_lines)
        ]

    async def _convert_to_scanned_issues(
        self, 
        results: list[tuple[Optional[LLMScanReport], str, Optional[Any]]], 
        file_path: str, 
        patched_file: PatchedFile,
    ) -> list[ScannedIssue]:
        """
        验证行号，并且将 LLMScannedIssue 转换为 ScannedIssue 对象，添加文件路径和上下文
        """
        scanned_issues = []
        added_lines = self._get_added_lines(patched_file)
        
        for report, hunk_context, result in results:
            if not report or not report.issues:
                continue

            for issue in report.issues:
                if issue.target_line in added_lines: # 校验报告的漏洞行号是否与新增行号有交集
                    # 获取漏洞行的上下文
                    context, _ = await self._get_context(file_path, issue.target_line, issue.target_line)
                    
                    scanned_issues.append(ScannedIssue(
                        scanner="llm",
                        name=issue.name,
                        path=file_path,
                        message=issue.information,
                        severity=issue.severity,
                        confidence_score=issue.confidence_score,
                        snippet_region=SnippetRegion(
                            start_line=issue.target_line,
                            end_line=issue.target_line
                        ),
                        snippet_text=issue.vulnerable_code_snippet,
                        context=context
                    ))
                    logger.info(
                        f"成功添加文件 {file_path} 中的漏洞: {issue.name}。"
                        f"\n代码上下文 {hunk_context} -> 漏洞 {scanned_issues[-1]}\n原始消息：{result}"
                    )
                else:
                    logger.info(
                        f"过滤掉文件 {file_path} 中的漏洞: {issue.name}。"
                        f"其行号 {issue.target_line} 不在 PR 增量范围内。"
                    )

        return scanned_issues

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
        提取目标行周边的上下文，以及代码文件的头部 import 部分
        对于 python 文件，基于 tree-sitter 提取
        对于其他文件，基于滑动窗口提取
        """
        try:
            suffix = Path(file_path).suffix.lower()

            if suffix == '.py':
                context, scope = await self.retriever.core_get_code_context(
                    file_path=file_path,
                    start_point=(start_line, 1),
                    end_point=(end_line, 1),
                    min_lines=10
                )
                return context, scope
            else:
                context, scope = await self.analyzer.core_get_file_context(
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