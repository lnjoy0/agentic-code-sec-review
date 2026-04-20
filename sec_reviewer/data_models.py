"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


@dataclass
class PRDetails:
    """Details of a pull request."""
    owner: str
    repo: str
    pull_number: int
    title: str
    description: str
    head_sha: Optional[str] = None
    base_sha: Optional[str] = None
    
    @property
    def repo_full_name(self) -> str:
        """Get the full repository name."""
        return f"{self.owner}/{self.repo}"


@dataclass
class FileInfo:
    """Information about a file in a diff."""
    path: str
    old_path: Optional[str] = None
    is_new_file: bool = False
    is_renamed_file: bool = False
    
    @property
    def is_binary(self) -> bool:
        """Check if the file is likely binary based on extension."""
        binary_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', 
            '.tar', '.gz', '.exe', '.dll', '.so', '.dylib'
        }
        return any(self.path.lower().endswith(ext) for ext in binary_extensions)
    
    @property
    def file_extension(self) -> str:
        """Get the file extension."""
        return self.path.split('.')[-1].lower() if '.' in self.path else ''


@dataclass
class HunkInfo:
    """Information about a hunk in a diff."""
    source_start: int
    source_length: int
    target_start: int
    target_length: int
    content: str
    header: str = ""
    lines: List[str] = field(default_factory=list)


@dataclass
class DiffFile:
    """Represents a file in a diff."""
    file_info: FileInfo
    hunks: List[HunkInfo] = field(default_factory=list)
    
    @property
    def total_additions(self) -> int:
        """Count total added lines."""
        return sum(1 for hunk in self.hunks for line in hunk.lines if line.startswith('+'))
    
    @property
    def total_deletions(self) -> int:
        """Count total deleted lines."""
        return sum(1 for hunk in self.hunks for line in hunk.lines if line.startswith('-'))


class ReviewPriority(Enum):
    """Priority levels for code review comments."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ReviewComment:
    """A code review comment."""
    body: str
    path: str
    position: int
    line_number: Optional[int] = None
    category: Optional[str] = None
    priority: Optional[ReviewPriority] = None
    suggestion: Optional[str] = None
    
    def to_github_comment(self) -> Dict[str, Any]:
        """Convert to GitHub API format."""
        return {
            "body": self.body,
            "path": self.path,
            "position": self.position
        }

@dataclass
class ReviewResult:
    """Result of a code review."""
    pr_details: PRDetails
    comments: List[ReviewComment] = field(default_factory=list)
    processed_files: int = 0
    skipped_files: int = 0
    errors: List[str] = field(default_factory=list)
    processing_time: Optional[float] = None
    
    @property
    def total_comments(self) -> int:
        """Get total number of comments."""
        return len(self.comments)
    
    @property
    def comments_by_priority(self) -> Dict[ReviewPriority, int]:
        """Get comment count by priority."""
        counts = {priority: 0 for priority in ReviewPriority}
        for comment in self.comments:
            counts[comment.priority] += 1
        return counts
    
    @property
    def success(self) -> bool:
        """Check if review was successful."""
        return len(self.errors) == 0


@dataclass
class AnalysisContext:
    """Context information for code analysis."""
    pr_details: PRDetails
    file_info: FileInfo
    related_files: List[str] = field(default_factory=list)
    project_context: Optional[str] = None
    language: Optional[str] = None
    
    @property
    def is_test_file(self) -> bool:
        """Check if this is a test file."""
        test_patterns = ['test_', '_test.', 'spec_', '_spec.', '/test/', '/tests/']
        return any(pattern in self.file_info.path.lower() for pattern in test_patterns)
