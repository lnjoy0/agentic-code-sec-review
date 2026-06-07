from typing import List, Dict, Any, Set
from unidiff import PatchedFile
from pathlib import Path
import logging
import asyncio
import json

from sec_reviewer.core.config import ScannerConfig, CodeRetrievalConfig
from sec_reviewer.core.data_models import ScannedIssue
from sec_reviewer.core.diff_parser import IGNORED_SUFFIXES
from sec_reviewer.tools.code_retriever import CodeRetriever
from sec_reviewer.tools.project_analyzer import ProjectAnalyzer


logger = logging.getLogger(__name__)


class HeuristicScanner:
    """传统启发式工具扫描器"""

    def __init__(self, scanner_config: ScannerConfig, retrieval_config: CodeRetrievalConfig):
        self.scanner_config = scanner_config
        self.retrieval_max_lines = int(retrieval_config.context_max_lines)
        self.retriever = CodeRetriever(scanner_config.workspace_dir, retrieval_config)
        self.analyzer = ProjectAnalyzer(scanner_config.workspace_dir, retrieval_config)
    
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

        rules = self.scanner_config.semgrep_rules
        severity = self.scanner_config.semgrep_severity
        rules_list = rules.split(' ')

        # 单个批次的执行逻辑
        async def process_chunk(file_chunk):
            async with semaphore:
                cmd_args = ["scan"] + file_chunk + rules_list + ["--json", f"--severity={severity}"]
                
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
            "--no-banner",
            "-f", "json",
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
            results = json.loads(stdout_str)
            if results and isinstance(results, list):
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
        severity = self.scanner_config.trivy_severity
        cmd = [
            "trivy", "fs", self.scanner_config.workspace_dir,
            "-f", "json", 
            "--severity", severity,
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
            results = data.get("Results", [])

            all_issues = []
            for res in results:
                target_path = res.get("Target", "")
                
                for vuln in res.get("Vulnerabilities", []): # SCA 依赖包漏洞
                    vuln["_trivy_target_path"] = target_path
                    all_issues.append(vuln)
                    
                for misconf in res.get("Misconfigurations", []): # IaC 配置漏洞 
                    misconf["_trivy_target_path"] = target_path
                    all_issues.append(misconf)

            if all_issues:
                filtered_results = self._filter_results(all_issues, patched_files)
                return await self._convert_to_scanned_issue(filtered_results, tool_name='trivy')
            return []
            
        except json.JSONDecodeError as e:
            logger.error(f"json decoding failed: {str(e)}")
            return []

    def _filter_results(self, all_results: List[Dict[str, Any]], patched_files: List[PatchedFile]) -> List[Dict[str, Any]]:
        """
        过滤与本次 PR 中新增或修改行无关的结果。
        """
        added_lines_by_file: Dict[str, Set[int]] = {}
        added_hunks_by_file: Dict[str, List[str]] = {}

        try:
            # 找出每个补丁文件中的新增行的行号和上下文
            for patched_file in patched_files:
                file_path = patched_file.path
                if file_path not in added_lines_by_file:
                    added_lines_by_file[file_path] = set()
                    added_hunks_by_file[file_path] = []

                for hunk in patched_file:
                    has_added_lines = False
                    hunk_text_lines = []
                    
                    for line in hunk:                       
                        if line.is_added:
                            added_lines_by_file[file_path].add(line.target_line_no)
                            hunk_text_lines.append(line.value.strip())
                            has_added_lines = True
                            
                    if has_added_lines:
                        added_hunks_by_file[file_path].append("\n".join(hunk_text_lines))

            # 通过找出的新增行号过滤results
            filtered_results = []
            for result in all_results:
                res_path = ""
                res_start = None
                res_end = None
                vuln_pkg_name = ""
                vuln_installed_ver = ""

                if "path" in result: # 解析semgrep的json结果
                    res_path = result.get("path", "")
                    res_start = result.get("start", {}).get("line")
                    res_end = result.get("end", {}).get("line")

                elif "_trivy_target_path" in result: 
                    res_path = result.get("_trivy_target_path", "")
                    vuln_pkg_name = result.get("PkgName", "") # 获取包名与版本号 (针对依赖漏洞)
                    vuln_installed_ver = result.get("InstalledVersion", "")

                    cause_meta = result.get("CauseMetadata", {}) # 获取行号（针对 IaC 漏洞）
                    if cause_meta:
                        res_start = cause_meta.get("StartLine")
                        res_end = cause_meta.get("EndLine")
                    
                    logger.info(result)
                    logger.info(added_lines_by_file.keys())
                    logger.info(f"added_lines_by_file: {added_lines_by_file}")
                    logger.info(f"added_hunks_by_file: {added_hunks_by_file}")

                if not res_path:
                    continue

                for diff_path in added_lines_by_file.keys():
                    if self._is_path_match(res_path, diff_path):
                        if res_start: # 按行号过滤
                            changed_lines = added_lines_by_file.get(diff_path, set())
                            res_end_line = res_end if res_end else res_start
                            if any(l in changed_lines for l in range(res_start, res_end_line + 1)):
                                filtered_results.append(result)
                        else:
                            if vuln_pkg_name: # 按漏洞包名和版本号过滤
                                modified_hunks = added_hunks_by_file.get(diff_path, [])
                                for hunk_text in modified_hunks:
                                    has_pkg = vuln_pkg_name in hunk_text
                                    has_ver = vuln_installed_ver in hunk_text if vuln_installed_ver else True
                                    if has_pkg and has_ver:
                                        filtered_results.append(result)
                                        break
                            else:
                                pass
                        break

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
        tool_name: str
    ) -> List[ScannedIssue]:
        """将原始结果转换成 ScannedIssue 结构"""
        scan_results = []
        for raw_result in raw_results:
            if tool_name == "semgrep": # semgrep 原生 json 格式
                path = raw_result.get("path", "")
                message = raw_result.get("extra", {}).get("message", "")

                report_cwe = raw_result.get("extra", {}).get("metadata", {}).get("cwe")
                cwe = report_cwe[0] if isinstance(report_cwe, list) else cwe

                snippet_region={
                    "start_line": raw_result.get("start", {}).get("line"),
                    "end_line": raw_result.get("end", {}).get("line"),
                    "start_column": raw_result.get("start", {}).get("col"),
                    "end_column": raw_result.get("end", {}).get("col")
                }

            elif tool_name == "trivy": # trivy 原生 json 格式
                path = raw_result.get("_trivy_target_path", "")
                cwe_ids = raw_result.get("CweIDs", [])
                cwe = cwe_ids[0] if cwe_ids and isinstance(cwe_ids, list) else 'Unknown (Trivy)'
                
                if "VulnerabilityID" in raw_result: # SCA 依赖漏洞
                    cve_id = raw_result.get("VulnerabilityID", "")
                    pkg_name = raw_result.get("PkgName", "")
                    title = raw_result.get("Title", "")
                    desc = raw_result.get("Description", "")
                    installed_ver = raw_result.get("InstalledVersion", "")
                    fixed_ver = raw_result.get("FixedVersion", "")
                    
                    message = f"[{cve_id}] {pkg_name} ({installed_ver}): {title}\nDescription: {desc}\nFixed Version: {fixed_ver}"
                    
                    snippet_region = {
                        "start_line": 1, "end_line": 1, "start_column": 1, "end_column": 1
                    }
                else: # IaC 配置文件问题 (如 Dockerfile)
                    cve_id = raw_result.get("ID", "")
                    title = raw_result.get("Title", "")
                    desc = raw_result.get("Description", "")
                    message = f"[{cve_id}] {title}\nDescription: {desc}"
                    
                    cause_meta = raw_result.get("CauseMetadata", {})
                    start_line = cause_meta.get("StartLine", 1)
                    snippet_region = {
                        "start_line": start_line,
                        "end_line": cause_meta.get("EndLine", start_line),
                        "start_column": 1,
                        "end_column": 1
                    }

            elif tool_name == "gitleaks": # gitleaks 原生 json 格式
                path = raw_result.get("File", "")
                
                rule_description = raw_result.get("Description", "Sensitive Information Detected")
                rule_id = raw_result.get("RuleID", "Unknown Rule")
                match_text = raw_result.get("Match", "N/A") # 泄漏的具体内容片段
                
                message = f"[{rule_id}] {rule_description}\nMatched Context: {match_text}"
                cwe = "CWE-798"
                
                snippet_region = {
                    "start_line": raw_result.get("StartLine", 1),
                    "end_line": raw_result.get("EndLine", raw_result.get("StartLine", 1)),
                    "start_column": raw_result.get("StartColumn", 1),
                    "end_column": raw_result.get("EndColumn", 1)
                }

            else: 
                logger.warning(f"Unknown tool name: {tool_name}")
                continue
            
            # 过滤文档文件和二进制文件
            if Path(path).suffix.lower() in IGNORED_SUFFIXES:
                logger.info(f"Skipping file: {path}")
                continue
        
            try: 
                safe_start_line = snippet_region.get("start_line") or 1
                safe_end_line = snippet_region.get("end_line") or safe_start_line
                safe_start_col = snippet_region.get("start_column") or 1
                safe_end_col = snippet_region.get("end_column") or safe_start_col

                snippet_text = await self.analyzer.core_get_file_snippet(
                        file_path=path,
                        start_point=(safe_start_line, safe_start_col),
                        end_point=(safe_end_line, safe_end_col)    
                    )
                
                if Path(path).suffix == '.py':
                    context, _ = await self.retriever.core_get_code_context(
                        file_path=path,
                        start_point=(safe_start_line, safe_start_col),
                        end_point=(safe_end_line, safe_end_col)
                    )
                else:
                    context, _ = await self.analyzer.core_get_file_context(
                        file_path=path, 
                        start_line=safe_start_line,
                        end_line=safe_end_line
                    )
            except Exception as e:
                logger.warning(f"Failed to retrieve code snippet for {tool_name} result at {path}:{snippet_region['start_line']}: {e}")
                continue

            issue = ScannedIssue(
                scanner=tool_name,
                path=path,
                message=message,
                cwe=cwe,
                snippet_region=snippet_region,
                snippet_text=snippet_text,
                context=context
            )
            scan_results.append(issue)

            logger.info(
                f"Heuristic Scanner 报告漏洞 id: {issue.id}, cwe: {cwe}, path: {path}, snippet region: {snippet_region}, snippet text: {snippet_text}, message: {message}"
            )

        return scan_results