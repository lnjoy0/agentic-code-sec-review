from typing import List, Dict, Any, Set, Optional
from unidiff import PatchedFile
from pathlib import Path
import logging
import asyncio
import json

from sec_reviewer.core.config import ScannerConfig, CodeRetrievalConfig
from sec_reviewer.core.data_models import ScannedIssue
from sec_reviewer.tools.code_retriever import CodeRetriever
from sec_reviewer.tools.project_analyzer import ProjectAnalyzer


logger = logging.getLogger(__name__)


class HeuristicScanner:
    """传统启发式工具扫描器"""

    def __init__(self, scanner_config: ScannerConfig, retrieval_config: CodeRetrievalConfig):
        self.scanner_config = scanner_config
    
    async def get_report(self, patched_files: List[PatchedFile]) -> Dict[str, List[ScannedIssue]]:
        """获取传统工具的扫描报告"""
        
        # 调用 Semgrep 扫描
        semgrep_results = await self._run_semgrep_sync(patched_files)
        logger.info(f"Semgrep scanned for {len(semgrep_results)} results")

        # 调用 gitleaks 扫描
        gitleaks_results = await self._run_gitleaks()
        logger.info(f"Gitleaks scanned for {len(gitleaks_results)} results")

        # 调用 trivy 扫描
        trivy_results = await self._run_trivy(patched_files)
        logger.info(f"Trivy scanned for {len(trivy_results)} results")

        return {
            "semgrep": semgrep_results,
            "gitleaks": gitleaks_results,
            "trivy": trivy_results
        }

    async def _run_semgrep_sync(self, patched_files: List[PatchedFile], batch_size: int = 200) -> List[ScannedIssue]:
        """
        semgrep利用Tree-sitter将源代码解析成AST，并使用预定义的规则集进行模式匹配
        semgrep免费版只支持对单个文件的分析，因此这里只传入变更文件，做增量扫描
        --severity=ERROR 只报告 ERROR 级别的漏洞
        """
        filenames = [f.path for f in patched_files] # f.path是新增或者修改后的文件路径
        logger.info("Semgrep running...")
        logger.info(f"Number of files changed: {len(filenames)}")
        logger.info(f"Changed files: {str(filenames)}")

        # 将文件列表切片，防止一次性传入过多文件导致命令行参数过长的问题
        chunks = [filenames[i:i + batch_size] for i in range(0, len(filenames), batch_size)]
        # 控制并发数量
        semaphore = asyncio.Semaphore(2)

        # 单个批次的执行逻辑
        async def process_chunk(file_chunk):
            async with semaphore:
                cmd_args = ["scan"] + file_chunk + [
                    "--config=p/default", "--config=p/security-audit", "--config=p/secrets", 
                    "--config=p/r2c-security-audit", "--config=p/insecure-transport",
                    "--config=p/python", "--config=p/django", "--config=p/flask", "--config=p/sql-injection", # python相关规则集
                    "--json", "--severity=ERROR", 
                    ]
                
                logger.info(f"run: semgrep {cmd_args}")
                process = await asyncio.create_subprocess_exec(
                    "semgrep", *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if process.returncode != 0 and stderr:
                    logger.warning(f"Semgrep Error: {stderr.decode()}")
                
                try:
                    return json.loads(stdout.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"json decoding failed: {str(e)}\n字符串: {stdout.decode('utf-8')}")
                    return []

        # 并行执行所有批次
        tasks = [process_chunk(chunk) for chunk in chunks]
        results = await asyncio.gather(*tasks)

        all_results = [item for result in results for item in result.get("results", [])]
        filtered_results = self._filter_results(all_results, patched_files)
        
        return await self._convert_to_scanned_issue(filtered_results, tool_name='semgrep')

    async def _run_gitleaks(self) -> List[ScannedIssue]:
        """
        gitleaks用于扫描敏感信息泄露，如 API 密钥、密码、证书等
        其使用正则匹配与香农熵分析等技术，对字符串做检测
        这里只做增量扫描，因此只传入 diff 内容
        """
        logger.info("Gitleaks running...")
        cmd = [
            "gitleaks", "detect", self.scanner_config.workspace_dir,
            f"--log-opts={self.scanner_config.base_sha}...{self.scanner_config.head_sha}", # 只扫描从 base 到 head 之间新增的 commits
            "--no-banner", "--redact", # --redact 不输出敏感信息详情
            "-f", "sarif",
            "-r", "-" # 将 JSON 报告输出到标准输出 (stdout)
        ]
        
        logger.info(f"run: {cmd}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 异步等待执行完成，并获取输出
            stdout_bytes, stderr_bytes = await process.communicate()
            
            stdout_str = stdout_bytes.decode('utf-8', errors='replace')
            stderr_str = stderr_bytes.decode('utf-8', errors='replace')
            
        except Exception as e:
            logger.error(f"Gitleaks 进程启动失败: {str(e)}")
            return []

        if stderr_str.strip():
            logger.warning(f"Gitleaks Log/Error: {stderr_str.strip()}")

        try:
            data = json.loads(stdout_str)
            runs = data.get("runs", [])
            if runs and len(runs) > 0:
                results = runs[0].get("results", [])
                return await self._convert_to_scanned_issue(results, tool_name='gitleaks')
            return []
        
        except json.JSONDecodeError as e:
            logger.error(f"json decoding failed: {str(e)}")
            return []

    async def _run_trivy(self, patched_files: List[PatchedFile]) -> List[ScannedIssue]:
        """
        Trivy用于进行第三方依赖扫描(SCA)，可以检查requirements.txt等依赖文件，其使用的漏洞库整合了包括GitHub Advisory、OSV等多种数据源
        此外，其会使用内置的规则集检查配置文件的安全性(IaC 扫描)，关注Dockerfile等文件
        """
        logger.info("Trivy running...")
        cmd = [
            "trivy", "fs", self.scanner_config.workspace_dir,
            "-f", "sarif", 
            "--severity", "HIGH,CRITICAL",
            "--cache-dir", "/home/runner/.cache/trivy"
        ]
        
        logger.info(f"run: {cmd}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = await process.communicate()

            stdout_str = stdout_bytes.decode('utf-8', errors='replace')
            stderr_str = stderr_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Trivy 进程启动失败: {str(e)}")
            return []

        if stderr_str.strip():
            logger.warning(f"Trivy Scanner Log/Error: {stderr_str.strip()}")

        try:
            data = json.loads(stdout_str)
            runs = data.get("runs", [])
            if runs and len(runs) > 0:
                results = runs[0].get("results", [])
                cve_list = runs[0].get("tool", {}).get("driver", {}).get("rules", [])
                filtered_results = self._filter_results(results, patched_files)
                return await self._convert_to_scanned_issue(filtered_results, tool_name='trivy', cve_list=cve_list)
            return []
        except json.JSONDecodeError as e:
            logger.error(f"json decoding failed: {str(e)}")
            return []

    def _filter_results(self, all_results: List[Dict[str, Any]], patched_files: List[PatchedFile]) -> List[Dict[str, Any]]:
        """
        过滤扫描到的结果，只保留与本次 PR 中新增或修改行相关的结果。
        """
        # 找出每个补丁文件中的新增行的行号
        added_lines_by_file: Dict[str, Set[int]] = {}

        try:
            for patched_file in patched_files:
                file_path = patched_file.path
                if file_path not in added_lines_by_file:
                    added_lines_by_file[file_path] = set()
                
                for hunk in patched_file:
                    for line in hunk:
                        if line.is_added:
                            added_lines_by_file[file_path].add(line.target_line_no)

            # 通过找出的新增行号过滤results
            filtered_results = []
            for result in all_results:
                if "path" in result: # 解析semgrep的json结果
                    res_path = result.get("path", "")
                    res_start = result.get("start", {}).get("line")
                    res_end = result.get("end", {}).get("line")

                elif "locations" in result and result["locations"]: # 解析trivy的sarif结果
                    loc = result["locations"][0].get("physicalLocation", {})
                    res_path = loc.get("artifactLocation", {}).get("uri")
                    res_start = loc.get("region", {}).get("startLine")
                    res_end = loc.get("region", {}).get("endLine")

                if not res_path:
                    continue

                for diff_path, changed_lines in added_lines_by_file.items():
                    if self._is_path_match(res_path, diff_path):
                        if not res_start:
                            filtered_results.append(result)
                        elif any(l in changed_lines for l in range(res_start, res_end+1)):
                            filtered_results.append(result)
                        break  # 找到匹配文件后停止

            return filtered_results
        except Exception as e:
            logger.error(f"Failed to filter scan results: {e}")
            return all_results

    def _is_path_match(self, path_one: str, path_two: str) -> bool:
        """匹配两个路径是否是同一个文件"""
        po = path_one.replace("\\", "/").strip("/")
        pt = path_two.replace("\\", "/").strip("/")
        
        # 完全相等，或者长路径以 "/短路径" 结尾
        return po == pt or po.endswith("/" + pt) or po.endswith("/" + pt)

    async def _convert_to_scanned_issue(
        self, 
        raw_results: List[Dict[str, Any]], 
        tool_name: str, 
        cve_list: Optional[List] = None
    ) -> List[ScannedIssue]:
        """将原始结果转换成 ScannedIssue 结构"""
        scan_results = []
        for raw_result in raw_results:
            if tool_name == "semgrep": # semgrep 输出的是自己的 json 格式，trivy 和 gitleaks 输出的是 sarif 格式
                path = raw_result.get("path", "")
                message = raw_result.get("extra", {}).get("message", "")

                report_cwe = raw_result.get("extra", {}).get("metadata", {}).get("cwe")
                cwe = report_cwe[0] if isinstance(report_cwe, list) else cwe
                logger.info(f"Semgrep 报告漏洞：{cwe}")

                snippet_region={
                    "start_line": raw_result.get("start", {}).get("line"),
                    "end_line": raw_result.get("end", {}).get("line"),
                    "start_column": raw_result.get("start", {}).get("col"),
                    "end_column": raw_result.get("end", {}).get("col")
                }
            else:
                path = raw_result.get("locations")[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                message = raw_result.get("message", {}).get("text", "")
                cwe = 'Unknown (Trivy or Gitleaks)'
                logger.info(f"Trivy or Gitleaks 报告漏洞：{cwe}")

                snippet_region = {
                    "start_line": raw_result.get("locations")[0].get("physicalLocation", {}).get("region", {}).get("startLine"),
                    "end_line": raw_result.get("locations")[0].get("physicalLocation", {}).get("region", {}).get("endLine"),
                    "start_column": raw_result.get("locations")[0].get("physicalLocation", {}).get("region", {}).get("startColumn"),
                    "end_column": raw_result.get("locations")[0].get("physicalLocation", {}).get("region", {}).get("endColumn")
                }
            
            # 为 trivy 的漏洞报告添加依赖相关的 CVE 详情 
            if cve_list:
                cve_details = ""
                cve_id = raw_result.get("ruleId", "")
                for cve in cve_list:
                    if cve.get("id", "") == cve_id:
                        cve_details = "CVE Details:\n" + cve.get('fullDescription', {}).get("text", "")
                message = message + '\n' + cve_details

            try: 
                analyzer = ProjectAnalyzer(self.scanner_config.workspace_dir)
                snippet_text = await analyzer.core_get_file_snippet(
                        file_path=path,
                        start_point=(snippet_region["start_line"], snippet_region["start_column"]),
                        end_point=(snippet_region["end_line"], snippet_region["end_column"])    
                    )
                
                if Path(path).suffix == '.py':
                    retriever = CodeRetriever(self.scanner_config.workspace_dir)
                    context, _ = await retriever.core_get_code_context(
                        file_path=path,
                        start_point=(snippet_region["start_line"], snippet_region["start_column"]),
                        end_point=(snippet_region["end_line"], snippet_region["end_column"])
                    )
                else:
                    context, _ = await analyzer.core_get_file_context(
                        file_path=path, 
                        start_line=snippet_region["start_line"],
                        end_line=snippet_region["end_line"]
                    )
            except Exception as e:
                logger.warning(f"Failed to retrieve code snippet for {tool_name} result at {path}:{snippet_region['start_line']}: {e}")
                continue

            scan_results.append(ScannedIssue(
                path=path,
                message=message,
                cwe=cwe,
                snippet_region=snippet_region,
                snippet_text=snippet_text,
                context=context
            ))

        return scan_results 