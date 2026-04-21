import asyncio
import logging
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set
from unidiff import PatchedFile

from .config import Config
from .data_models import (
    PRDetails, ReviewResult, ReviewComment, HunkInfo
)
from .github_client import GitHubClient, GitHubClientError
from .diff_parser import DiffParser, DiffParsingError


logger = logging.getLogger(__name__)


class ReviewerError(Exception):
    """Base exception for code reviewer errors."""
    pass


class CodeSecReviewer:
    """Main orchestrator class for the code review process."""
    
    def __init__(self, config: Config):
        """Initialize the code reviewer with configuration."""
        self.config = config
        
        # Initialize components
        self.github_client = GitHubClient(config.github)
        self.diff_parser = DiffParser()

    async def review_pull_request(self, event_path: str, codeql_results_dir: str, language: str,
                                  base_sha: str, head_sha: str) -> ReviewResult:
        """Main entry point for reviewing a pull request."""
        logger.info("Starting PR review process...")
        all_comments: List[ReviewComment] = []

        try:
            # 解析 GitHub Action event.json 获取 PR 详情 
            pr_details = self.github_client.get_pr_details_from_event(event_path)

            # 获取 PR 的 diff 信息，并解析成结构化的 PatchedFile 对象列表
            diff_content = await self._get_pr_diff(pr_details)
            patched_files = await self._parse_diff(diff_content)

            # 要扫描的代码已经被 actions/checkout 提取到了当前工作目录
            workspace_dir = "." 

            # 调用 Semgrep 扫描
            semgrep_results = await self._run_semgrep_sync(patched_files, language)
            logger.info(f"Semgrep scanned for {len(semgrep_results)} results")

            # 调用 gitleaks 扫描
            gitleaks_results = self._run_gitleaks(workspace_dir, base_sha, head_sha)
            logger.info(f"Gitleaks scanned for {len(gitleaks_results)} results")

            # 调用 trivy 扫描
            trivy_results = self._run_trivy(workspace_dir)
            logger.info(f"Trivy scanned for {len(trivy_results)} results")

            # # 读取 CodeQL 的结果
            codeql_results = self._read_codeql_results(codeql_results_dir, language)
            logger.info(f"CodeQL scanned for {len(codeql_results)} results")

            # 整合扫描结果
            all_results = {
                "semgrep": semgrep_results,
                "gitleaks": gitleaks_results,
                "trivy": trivy_results,
                "codeql": codeql_results
            }
            all_comments = self._convert_results_to_comments(all_results, patched_files)

            # 将评论提交到 GitHub
            if all_comments:
                success = await self._create_github_review(pr_details, all_comments)
                if not success:
                    logger.error("Failed to post review comments to GitHub.")

            return ReviewResult(
                pr_details=pr_details,
                comments=all_comments,
            )

        except Exception as e:
            logger.error(f"Error during PR review: {e}")
            raise ReviewerError(f"Review process failed: {e}")

    def _convert_results_to_comments(self, results: Dict[str, Any], patched_files: List[PatchedFile]) -> List[ReviewComment]:
        """Convert raw scanner results to GitHub review comments."""
        comments = []
        for tool, tool_results in results.items():                        
            comment = ReviewComment(
                body=json.dumps(tool_results[:1000], indent=4),
                path=patched_files[0].file_info.path,
                position=1
            )
            comments.append(comment)
        
        return comments

    async def _run_semgrep_sync(self, patched_files: List[PatchedFile], lang: str = '', batch_size: int = 200) -> List[Dict[str, Any]]:
        """
        semgrep利用Tree-sitter将源代码解析成抽象语法树 (AST)，并使用预定义的规则集对AST进行模式匹配
        semgrep免费版（不登陆）是对单个文件的AST做模式匹配，不会进行跨文件分析，因此这里只传入变更文件，做增量扫描
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
                    "--json", "--severity=ERROR", 
                    # "--quiet"
                    ]
                
                if lang:
                    if lang == "python":
                        cmd_args += ["--config=p/python", "--config=p/django", 
                                "--config=p/flask", "--config=p/sql-injection"]
                    elif lang == "java":
                        cmd_args += ["--config=p/java", "--config=p/spring", 
                                "--config=p/hibernate", "--config=p/xxe"]
                    elif lang == "go":
                        cmd_args += ["--config=p/golang", "--config=p/gosec"]

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
                        logger.error(f"json decoding failed: {str(e)}")
                        return []

        # 并行执行所有批次
        tasks = [process_chunk(chunk) for chunk in chunks]
        results = await asyncio.gather(*tasks)

        all_results = [item for sublist in results for item in sublist.get("results", [])]
        filtered_results = self._filter_results(all_results, patched_files)
        
        return filtered_results

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

    def _run_gitleaks(self, target_dir: str, base_sha: str, head_sha: str) -> List[Dict[str, Any]]:
        """
        gitleaks用于扫描敏感信息泄露，如 API 密钥、密码、证书等
        其使用正则匹配与香农熵分析等技术，对字符串做检测
        这里只做增量扫描，因此只传入 diff 内容
        """
        logger.info("Gitleaks running...")
        cmd = [
            "gitleaks", "detect", target_dir,
            f"--log-opts={base_sha}...{head_sha}", # 只扫描从 base 到 head 之间新增的 commits
            "--no-banner", "--redact", # --redact 不输出敏感信息详情
            # "--log-level", "error",
            "-f", "sarif",
            "-r", "-" # 将 JSON 报告输出到标准输出 (stdout)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stderr.strip():
            logger.warning(f"Gitleaks Log/Error: {result.stderr.strip()}")

        try:
            data = json.loads(result.stdout)
            runs = data.get("runs", [])
            if runs and len(runs) > 0:
                return runs[0].get("results", [])
            return []
        except json.JSONDecodeError as e:
            logger.error(f"json decoding failed: {str(e)}")
            return []

    def _run_trivy(self, target_dir: str) -> List[Dict[str, Any]]:
        """
        Trivy用于进行第三方依赖扫描(SCA)，可以检查requirements.txt等依赖文件，其使用的漏洞库整合了包括GitHub Advisory、OSV等多种数据源
        此外，其会使用内置的规则集检查配置文件的安全性(IaC 扫描)，关注Dockerfile等文件
        """
        logger.info("Trivy running...")
        cmd = [
            "trivy", "fs", target_dir,
            "-f", "sarif", 
            # "-q",
            "--severity", "HIGH,CRITICAL",
            "--cache-dir", "/tmp/trivy_cache"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stderr.strip():
            logger.warning(f"Trivy Scanner Log/Error: {result.stderr.strip()}")

        try:
            data = json.loads(result.stdout)
            runs = data.get("runs", [])
            if runs and len(runs) > 0:
                return runs[0].get("results", [])
            return []
        except json.JSONDecodeError as e:
            logger.error(f"json decoding failed: {str(e)}")
            return []

    def _read_codeql_results(self, results_dir: str, lang: str) -> List[Dict[str, Any]]:
        """
        codeql会把源码编译成关系型数据库，能够通过预定义规则查询代码里的漏洞
        它的主要特点是能够进行数据流与污点分析，而不是简单的模式匹配，因此能够发现更复杂的漏洞
        主要关注以下几点：
        1.Source: 外部输入（如用户的 HTTP 请求参数）
        2.Sink: 敏感操作（如执行 SQL 语句或系统命令）
        3.Taint Tracking: 自动分析不可信的数据是否能在不经过滤的情况下，从 Source 流向 Sink
        """
        logger.info("Reading CodeQL results...")
        try:
            with open(f"{results_dir}/{lang}.sarif", "r") as f:
                data = json.load(f)
                runs = data.get("runs", [])
                if runs and len(runs) > 0:
                    return runs[0].get("results", [])
                return []
        except Exception as e:
            print(f"Error reading CodeQL results: {e}")
            return []

    async def _get_pr_diff(self, pr_details: PRDetails) -> str:
        """Get PR diff with error handling."""
        try:
            logger.info("Fetching PR diff...")
            diff_content = self.github_client.get_pr_diff(
                pr_details.owner, pr_details.repo, pr_details.pull_number
            )
            return diff_content
        except GitHubClientError as e:
            logger.error(f"Failed to get PR diff: {str(e)}")
            return ""
    
    async def _parse_diff(self, diff_content: str) -> List[PatchedFile]:
        """Parse diff content with error handling."""
        try:
            logger.info("Parsing diff content...")
            patched_files = self.diff_parser.parse_diff(diff_content)
            return patched_files
        except DiffParsingError as e:
            logger.error(f"Failed to parse diff: {str(e)}")
            return []
            
    async def _analyze_files_concurrently(
        self, 
        patched_files: List[PatchedFile], 
        pr_details: PRDetails
    ) -> List[ReviewComment]:
        """Analyze files concurrently for improved performance."""
        
        all_comments = []
        
        # Process files in chunks to manage resources
        chunk_size = self.config.performance.chunk_size
        max_workers = min(self.config.performance.max_concurrent_files, len(patched_files))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file analysis tasks
            future_to_file = {
                executor.submit(self._analyze_single_file_sync, diff_file, pr_details): diff_file
                for diff_file in patched_files
            }
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_file):
                diff_file = future_to_file[future]
                
                try:
                    file_comments = future.result()
                    all_comments.extend(file_comments)
                    self.stats.files_processed += 1
                    
                    
                except Exception as e:
                    self.stats.errors_encountered += 1
        
        return all_comments
    
    def _analyze_single_file_sync(self, diff_file: PatchedFile, pr_details: PRDetails) -> List[ReviewComment]:
        """Synchronous wrapper for analyzing a single file (for thread pool)."""
        return asyncio.run(self._analyze_single_file(diff_file, pr_details))
    
    async def _analyze_single_file(self, diff_file: PatchedFile, pr_details: PRDetails) -> List[ReviewComment]:
        """Analyze a single file and return review comments."""
        pass
        
    def _convert_to_review_comment(
        self,
        ai_response,
        diff_file: PatchedFile,
        hunk: HunkInfo,
        hunk_index: int,
        cumulative_position: int
    ) -> Optional[ReviewComment]:
        """Convert AI response to GitHub review comment."""
        try:
            # The AI returns a line_number relative to the hunk (1-based)
            # We need to convert this to an absolute position in the diff (1-based)
            # GitHub's position is the line number in the diff, counting from the start of the file's diff
            
            line_number_in_hunk = ai_response.line_number
            
            # Ensure line number is within hunk bounds
            if line_number_in_hunk < 1 or line_number_in_hunk > len(hunk.lines):
                return None
            
            # Calculate the absolute position in the diff
            # cumulative_position is the number of lines before this hunk
            # ai_response.line_number is 1-based within the hunk
            position = cumulative_position + line_number_in_hunk
            
            # Validate the line is an added or modified line (starts with '+' or ' ')
            # GitHub only allows comments on lines that are in the new version of the file
            hunk_line = hunk.lines[line_number_in_hunk - 1]  # Convert to 0-based index
            if hunk_line.startswith('-'):
                # Try to find the next added or context line
                for i in range(line_number_in_hunk, len(hunk.lines) + 1):
                    if i <= len(hunk.lines) and not hunk.lines[i - 1].startswith('-'):
                        position = cumulative_position + i
                        break
                else:
                    return None
            
            comment = ReviewComment(
                body=ai_response.review_comment,
                path=diff_file.file_info.path,
                position=position,
                line_number=ai_response.line_number,
                priority=ai_response.priority,
                category=ai_response.category
            )
            
            return comment
            
        except Exception as e:
            return None
    
    async def _create_github_review(self, pr_details: PRDetails, comments: List[ReviewComment]) -> bool:
        """Create GitHub review with comments."""
        try:            
            success = self.github_client.create_review(pr_details, comments)
            
            return success
            
        except GitHubClientError as e:
            return False
        
    def close(self):
        """Clean up resources."""
        try:
            self.github_client.close()
        except Exception as e:
            pass
        
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
