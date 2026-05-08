import logging
from typing import List

from core.config import Config
from core.data_models import ReviewResult, ReviewComment
from core.github_client import GitHubClient
from core.diff_parser import DiffParser
from workflow.graph import app


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

    async def run(self) -> ReviewResult:
        """Main entry point for reviewing a pull request."""
        logger.info("Starting PR review process...")
        all_comments: List[ReviewComment] = []

        try:
            # 解析 GitHub Action event.json 获取 PR 详情 
            pr_details = self.github_client.get_pr_details_from_event()

            # 获取 PR 的 diff 信息，并解析成结构化的 PatchedFile 对象列表
            logger.info("Fetching PR diff...")
            diff_content = self.github_client.get_pr_diff(pr_details)
            
            logger.info("Parsing diff content...")
            patched_files = self.diff_parser.parse_diff(diff_content)

            # 初始化工作流状态，并传入配置信息
            initial_state = {
                'patched_files': patched_files
            }
            workflow_config = {'configurable': {
                'scanner_config': self.config.scanner,
                'llm_config': self.config.llm,
                'agent_config': self.config.agent,
                'code_retriever_config': self.config.code_retriever
            }}

            # 启动多智能体工作流，得到最终评论
            all_comments = await app.invoke(initial_state, config=workflow_config)

            # 将评论提交到 GitHub
            if all_comments:
                success = self.github_client.create_review(pr_details, all_comments)
                if not success:
                    logger.error("Failed to post review comments to GitHub.")

            return ReviewResult(
                pr_details=pr_details,
                comments=all_comments,
            )

        except Exception as e:
            logger.error(f"Error during PR review: {e}")
            raise ReviewerError(f"Review process failed: {e}")
                                
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
