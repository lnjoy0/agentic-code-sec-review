"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

import logging
import re
from typing import List, Dict, Any, Optional
from unidiff import PatchSet, PatchedFile, Hunk

from .data_models import DiffFile, FileInfo, HunkInfo


logger = logging.getLogger(__name__)


class DiffParsingError(Exception):
    """Exception raised when diff parsing fails."""
    pass


class DiffParser:
    """Parser for GitHub diff content with comprehensive error handling."""
    def __init__(self):
        logger.debug("Initialized diff parser")
    
    def parse_diff(self, diff_content: str) -> List[DiffFile]:
        """Parse diff content into structured DiffFile objects."""
        if not diff_content or not isinstance(diff_content, str):
            logger.warning("Empty or invalid diff content provided")
            return []
        
        logger.info(f"Parsing diff content (length: {len(diff_content)} characters)")
        
        try:
            diff_files = self._parse_with_unidiff(diff_content)
            logger.info(f"Successfully parsed {len(diff_files)} files using unidiff")
            return diff_files
        except Exception as e:
            logger.warning(f"Unidiff parsing failed: {str(e)}")
            logger.debug(f"Diff content preview: {diff_content[:500]}...")
            raise DiffParsingError(f"Failed to parse diff: {str(e)}")
    
    def _parse_with_unidiff(self, diff_content: str) -> List[DiffFile]:
        """Parse diff using the unidiff library."""
        try:
            patch_set = PatchSet(diff_content)
            logger.info(f"🔍 Unidiff PatchSet created with {len(patch_set)} files")
            
            # If no files found, show diff preview for debugging
            if len(patch_set) == 0:
                logger.warning(f"PatchSet is empty! Diff preview (first 1000 chars):")
                logger.warning(f"Diff content: {repr(diff_content[:1000])}")
                lines = diff_content.split('\n')
                logger.warning(f"Total lines: {len(lines)}")
                logger.warning(f"First 10 lines: {lines[:10]}")
                
            diff_files = []
            
            for i, patched_file in enumerate(patch_set):
                logger.debug(f"Processing patched file {i+1}: {patched_file.source_file} -> {patched_file.target_file}")
                diff_file = self._convert_patched_file(patched_file)
                if diff_file:
                    diff_files.append(diff_file)
                    logger.debug(f"✅ Successfully converted file: {diff_file.file_info.path}")
                else:
                    logger.debug(f"⚠️ Skipped file: {patched_file.source_file} -> {patched_file.target_file}")
            
            logger.info(f"Unidiff parsing completed: {len(diff_files)} files processed, {len(patch_set) - len(diff_files)} skipped")
            return diff_files
            
        except Exception as e:
            logger.warning(f"Unidiff parsing error: {str(e)}")
            logger.debug(f"Diff content preview: {diff_content[:1000]}...")
            raise
    
    def _convert_patched_file(self, patched_file: PatchedFile) -> Optional[DiffFile]:
        """Convert unidiff PatchedFile to our DiffFile model."""
        if not patched_file:
            logger.warning("Received empty patched file")
            return None
        if patched_file.is_removed_file: # 排除删除文件的情况
            logger.debug(f"File marked as removed: {patched_file.source_file}")
            return None
        
        try:
            # Extract file information
            target_file = patched_file.target_file or ""
            source_file = patched_file.source_file or ""
            
            if target_file:
                file_path = target_file[2:] if target_file.startswith("b/") else target_file
                old_path = source_file[2:] if source_file.startswith("a/") else source_file
            else:
                logger.warning(f"Missing target file path for patched file: {patched_file}")
                return None
            
            # Create FileInfo
            file_info = FileInfo(
                path=file_path,
                old_path=old_path,
                is_new_file=patched_file.is_added_file,
                is_renamed_file=patched_file.is_rename
            )
            
            # Skip binary files
            if file_info.is_binary:
                logger.debug(f"⚠️ Skipping binary file: {file_path}")
                return None
            
            # Convert hunks
            hunks = []
            for hunk in patched_file:
                hunk_info = self._convert_hunk(hunk)
                if hunk_info:
                    hunks.append(hunk_info)
            
            if not hunks:
                logger.debug(f"⚠️ No valid hunks found for file: {file_path}")
                return None
            
            diff_file = DiffFile(file_info=file_info, hunks=hunks)
            
            logger.debug(f"Converted file: {file_path} with {len(hunks)} hunks")
            return diff_file
            
        except Exception as e:
            logger.warning(f"Error converting patched file: {str(e)}")
            return None
    
    def _convert_hunk(self, hunk: Hunk) -> Optional[HunkInfo]:
        """Convert unidiff Hunk to our HunkInfo model."""
        try:
            # Extract hunk lines
            lines = []
            for line in hunk:
                line_content = str(line)
                lines.append(line_content)
            
            if not lines:
                logger.debug("Empty hunk found")
                return None
            
            # Create HunkInfo
            hunk_info = HunkInfo(
                source_start=hunk.source_start,
                source_length=hunk.source_length,
                target_start=hunk.target_start,
                target_length=hunk.target_length,
                content='\n'.join(lines),
                header=str(hunk).split('\n')[0],  # First line is the hunk header
                lines=lines
            )
            
            return hunk_info
            
        except Exception as e:
            logger.warning(f"Error converting hunk: {str(e)}")
            return None
    
    @staticmethod
    def get_file_language(file_path: str) -> Optional[str]:
        """Detect programming language from file extension."""
        if not file_path or '.' not in file_path:
            return None
        
        extension = file_path.split('.')[-1].lower()
        language_mapping = {
            'py': 'Python', 'js': 'JavaScript', 'ts': 'TypeScript',
            'jsx': 'React', 'tsx': 'TypeScript React',
            'java': 'Java', 'cpp': 'C++', 'c': 'C', 'cs': 'C#',
            'go': 'Go', 'rs': 'Rust', 'php': 'PHP', 'rb': 'Ruby',
            'swift': 'Swift', 'kt': 'Kotlin', 'scala': 'Scala',
            'html': 'HTML', 'css': 'CSS', 'scss': 'SCSS',
            'json': 'JSON', 'yaml': 'YAML', 'yml': 'YAML',
            'sql': 'SQL', 'sh': 'Shell', 'bash': 'Bash'
        }
        return language_mapping.get(extension)