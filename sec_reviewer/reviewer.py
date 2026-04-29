import asyncio
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set
from unidiff import PatchedFile

from .config import Config
from .data_models import (
    PRDetails, ReviewResult, ReviewComment, HunkInfo
)
from .github_client import GitHubClient, GitHubClientError
from .diff_parser import DiffParser, DiffParsingError
from .heuristic_scanner import HeuristicScanner


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
        self.heuristic_scanner = HeuristicScanner(config.scanner)

    async def review_pull_request(self) -> ReviewResult:
        """Main entry point for reviewing a pull request."""
        logger.info("Starting PR review process...")
        all_comments: List[ReviewComment] = []

        try:
            # 解析 GitHub Action event.json 获取 PR 详情 
            pr_details = self.github_client.get_pr_details_from_event()

            # 获取 PR 的 diff 信息，并解析成结构化的 PatchedFile 对象列表
            diff_content = await self._get_pr_diff(pr_details)
            patched_files = await self._parse_diff(diff_content)

            # 获取传统工具扫描结果
            heuristic_report = self.heuristic_scanner.get_report(patched_files)

            all_comments = self._convert_results_to_comments(heuristic_report, patched_files)

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
                body=json.dumps(tool_results[:100], indent=4),
                path=patched_files[0].path,
                position=1
            )
            comments.append(comment)
        
        return comments

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
