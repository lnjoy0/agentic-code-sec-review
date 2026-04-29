"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

import json
import logging
import requests
from typing import List, Dict, Any, Optional
from github import Github
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .config import GitHubConfig
from .data_models import PRDetails, ReviewComment


logger = logging.getLogger(__name__)


class GitHubClientError(Exception):
    """Base exception for GitHub client errors."""
    pass


class PRNotFoundError(GitHubClientError):
    """Exception raised when PR is not found."""
    pass


class RateLimitError(GitHubClientError):
    """Exception raised when GitHub API rate limit is exceeded."""
    pass


class GitHubClient:
    """GitHub API client with retry logic and comprehensive error handling."""
    
    def __init__(self, config: GitHubConfig):
        """Initialize GitHub client with configuration."""
        self.config = config
        self._client = Github(config.token)
        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Bearer {config.token}',
            'User-Agent': 'Agentic-Code-Sec-Reviewer/1.0',
            'Accept': 'application/vnd.github.v3+json'
        })
        
        logger.info("Initialized GitHub client")
    
    def get_pr_details_from_event(self) -> PRDetails:
        """Extract PR details from GitHub Actions event payload."""
        try:
            with open(self.config.event_path, "r") as f:
                event_data = json.load(f)
            logger.info("Successfully loaded GitHub event data")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load GitHub event data: {str(e)}")
            raise GitHubClientError(f"Failed to load event data: {str(e)}")
        
        pull_number = event_data["number"]
        repo_full_name = event_data["repository"]["full_name"]
        
        if not repo_full_name or "/" not in repo_full_name:
            raise GitHubClientError(f"Invalid repository name: {repo_full_name}")
        
        owner, repo = repo_full_name.split("/", 1)
        logger.info(f"Processing PR #{pull_number} in repository {repo_full_name}")
        
        try:
            pr_details = self.get_pr_details(owner, repo, pull_number)
            logger.info(f"Successfully retrieved PR details: {pr_details.title}")
            return pr_details
        except Exception as e:
            logger.error(f"Failed to get PR details: {str(e)}")
            raise GitHubClientError(f"Failed to get PR details: {str(e)}")
    
    def get_pr_details(self, owner: str, repo: str, pull_number: int) -> PRDetails:
        """Get pull request details."""
        logger.debug(f"Fetching PR details for {owner}/{repo}#{pull_number}")
        
        try:
            repo_obj = self._get_repo_with_retry(f"{owner}/{repo}")
            pr = self._get_pr_with_retry(repo_obj, pull_number)
            
            # Sanitize PR title and description
            title = self._sanitize_input(pr.title or "")
            description = self._sanitize_input(pr.body or "")
            
            pr_details = PRDetails(
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                title=title,
                description=description,
                head_sha=pr.head.sha,
                base_sha=pr.base.sha
            )
            
            logger.debug(f"Retrieved PR details: {title}")
            return pr_details
            
        except Exception as e:
            logger.warning(f"Failed to get PR details: {str(e)}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, Exception))
    )
    def _get_repo_with_retry(self, repo_name: str):
        """Get repository with retry logic."""
        logger.debug(f"Attempting to get repository: {repo_name}")
        try:
            return self._client.get_repo(repo_name)
        except Exception as e:
            logger.warning(f"Failed to get repository {repo_name}: {str(e)}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, Exception))
    )
    def _get_pr_with_retry(self, repo, pull_number: int):
        """Get pull request with retry logic."""
        logger.debug(f"Attempting to get PR #{pull_number}")
        try:
            return repo.get_pull(pull_number)
        except Exception as e:
            if "404" in str(e):
                raise PRNotFoundError(f"PR #{pull_number} not found")
            logger.warning(f"Failed to get PR #{pull_number}: {str(e)}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, requests.exceptions.Timeout))
    )
    def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        """Fetch the diff of a pull request with retry logic."""
        # Validate inputs
        if not all([owner, repo, pull_number]):
            logger.error("Invalid parameters provided to get_pr_diff")
            raise GitHubClientError("Invalid parameters")
        
        if not isinstance(pull_number, int) or pull_number <= 0:
            logger.error(f"Invalid pull request number: {pull_number}")
            raise GitHubClientError(f"Invalid pull request number: {pull_number}")
        
        repo_name = f"{self._sanitize_input(owner)}/{self._sanitize_input(repo)}"
        logger.info(f"Fetching diff for: {repo_name} PR#{pull_number}")
        
        try:
            api_url = f"{self.config.api_base_url}/repos/{repo_name}/pulls/{pull_number}.diff"
            diff_headers = {
                'Accept': 'application/vnd.github.v3.diff'
            }
            
            logger.debug(f"Making diff API request to: {api_url}")
            response = self._session.get(api_url, headers=diff_headers, timeout=self.config.timeout)
            
            if response.status_code == 200:
                diff = response.text
                logger.info(f"Successfully retrieved diff (length: {len(diff)} characters)")
                return diff
            elif response.status_code == 404:
                raise PRNotFoundError(f"PR #{pull_number} not found in {repo_name}")
            elif response.status_code == 403:
                if "rate limit" in response.text.lower():
                    raise RateLimitError("GitHub API rate limit exceeded")
                else:
                    raise GitHubClientError("Access forbidden - check GitHub token permissions")
            else:
                logger.error(f"Failed to get diff. Status code: {response.status_code}")
                logger.debug(f"Response content: {response.text[:500]}...")
                response.raise_for_status()  # This will trigger retry
                return ""
        
        except requests.exceptions.Timeout:
            logger.error("Request timed out while fetching diff")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed while fetching diff: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error while fetching diff: {str(e)}")
            raise GitHubClientError(f"Failed to fetch diff: {str(e)}")
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, Exception))
    )
    def create_review(self, pr_details: PRDetails, comments: List[ReviewComment]) -> bool:
        """Create a review with comments on GitHub with retry logic."""
        if not comments:
            logger.warning("No comments provided for review creation")
            return False
        
        logger.info(f"Creating review with {len(comments)} comments for PR #{pr_details.pull_number}")
        
        try:
            repo_obj = self._get_repo_with_retry(pr_details.repo_full_name)
            pr = self._get_pr_with_retry(repo_obj, pr_details.pull_number)
            
            # Validate and convert comments
            github_comments = []
            for comment in comments:
                if not isinstance(comment, ReviewComment):
                    logger.warning(f"Invalid comment type: {type(comment)}")
                    continue
                
                github_comment = self._validate_and_sanitize_comment(comment)
                if github_comment:
                    github_comments.append(github_comment)
            
            if not github_comments:
                logger.warning("No valid comments found after validation")
                return False
            
            logger.info(f"Creating review with {len(github_comments)} valid comments")
            
            # Create the review
            review_body = "test review body"
            review = pr.create_review(
                body=review_body,
                comments=github_comments,
                event="COMMENT"
            )
            
            logger.info(f"✅ Review created successfully with ID: {review.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create review: {str(e)}")
            raise GitHubClientError(f"Failed to create review: {str(e)}")
    
    def _validate_and_sanitize_comment(self, comment: ReviewComment) -> Optional[Dict[str, Any]]:
        """Validate and sanitize a review comment."""
        try:
            # Check required fields
            if not all([comment.body, comment.path]):
                logger.warning(f"Comment missing required fields: {comment}")
                return None
            
            # Validate position
            if not isinstance(comment.position, int) or comment.position <= 0:
                logger.warning(f"Invalid position {comment.position} in comment")
                return None
            
            # Sanitize content (preserve markdown in body, but sanitize path)
            sanitized_comment = {
                'body': self._sanitize_input(str(comment.body), preserve_markdown=True),
                'path': self._sanitize_input(str(comment.path), preserve_markdown=False),
                'position': comment.position
            }
            
            return sanitized_comment
            
        except Exception as e:
            logger.warning(f"Error validating comment: {str(e)}")
            return None
    
    @staticmethod
    def _sanitize_input(text: str, preserve_markdown: bool = False) -> str:
        """Sanitize user input to prevent injection attacks."""
        if not isinstance(text, str):
            return str(text) if text is not None else ""
        
        if preserve_markdown:
            # For markdown content (like comment bodies), only remove dangerous control characters
            # Don't HTML escape as it breaks markdown formatting in GitHub
            sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')
            return sanitized.strip()
        else:
            import html
            # HTML escape to prevent XSS (only for non-markdown fields like paths)
            sanitized = html.escape(text)
            
            # Remove potential command injection characters
            dangerous_chars = ['`', '$', '$(', '${', '|', '&&', '||', ';', '&']
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '')
            
            return sanitized.strip()
    
    def close(self):
        """Clean up resources."""
        if hasattr(self, '_session'):
            self._session.close()
        logger.debug("GitHub client closed")
