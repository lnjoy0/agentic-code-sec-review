from typing import List, Dict, Any, Set
from unidiff import PatchedFile
import logging
import asyncio
import json
import subprocess

from .config import ScannerConfig


logger = logging.getLogger(__name__)


class HeuristicScanner:
    """传统启发式工具扫描类"""

    def __init__(self, config: ScannerConfig):
        self.config = config
    
    async def get_report(self, patched_files: List[PatchedFile]) -> Dict[str, Any]:
        """获取传统工具的扫描报告"""
        
        # 调用 Semgrep 扫描
        semgrep_results = await self._run_semgrep_sync(patched_files)
        logger.info(f"Semgrep scanned for {len(semgrep_results)} results")

        # 调用 gitleaks 扫描
        gitleaks_results = self._run_gitleaks()
        logger.info(f"Gitleaks scanned for {len(gitleaks_results)} results")

        # 调用 trivy 扫描
        trivy_results = self._run_trivy(patched_files)
        logger.info(f"Trivy scanned for {len(trivy_results)} results")

        return {
            "semgrep": semgrep_results,
            "gitleaks": gitleaks_results,
            "trivy": trivy_results
        }

    async def _run_semgrep_sync(self, patched_files: List[PatchedFile], batch_size: int = 200) -> List[Dict[str, Any]]:
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
                    "--json", "--severity=ERROR", 
                    ]
                
                if self.lang == "python":
                    cmd_args += ["--config=p/python", "--config=p/django", 
                            "--config=p/flask", "--config=p/sql-injection"]
                elif self.lang == "java":
                    cmd_args += ["--config=p/java", "--config=p/spring", 
                            "--config=p/hibernate", "--config=p/xxe"]
                elif self.lang == "go":
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

    def _run_gitleaks(self) -> List[Dict[str, Any]]:
        """
        gitleaks用于扫描敏感信息泄露，如 API 密钥、密码、证书等
        其使用正则匹配与香农熵分析等技术，对字符串做检测
        这里只做增量扫描，因此只传入 diff 内容
        """
        logger.info("Gitleaks running...")
        cmd = [
            "gitleaks", "detect", self.workspace_dir,
            f"--log-opts={self.base_sha}...{self.head_sha}", # 只扫描从 base 到 head 之间新增的 commits
            "--no-banner", "--redact", # --redact 不输出敏感信息详情
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

    def _run_trivy(self, patched_files: List[PatchedFile]) -> List[Dict[str, Any]]:
        """
        Trivy用于进行第三方依赖扫描(SCA)，可以检查requirements.txt等依赖文件，其使用的漏洞库整合了包括GitHub Advisory、OSV等多种数据源
        此外，其会使用内置的规则集检查配置文件的安全性(IaC 扫描)，关注Dockerfile等文件
        """
        logger.info("Trivy running...")
        cmd = [
            "trivy", "fs", self.workspace_dir,
            "-f", "sarif", 
            "--severity", "HIGH,CRITICAL",
            "--cache-dir", "/home/runner/.cache/trivy"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stderr.strip():
            logger.warning(f"Trivy Scanner Log/Error: {result.stderr.strip()}")

        try:
            data = json.loads(result.stdout)
            runs = data.get("runs", [])
            if runs and len(runs) > 0:
                results = runs[0].get("results", [])
                return self._filter_results(results, patched_files)
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
