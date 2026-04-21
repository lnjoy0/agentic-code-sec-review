"""
Modified from [truongnh1992/gemini-ai-code-reviewer]
"""

import logging
from typing import List, Dict, Any, Optional
from unidiff import PatchSet, PatchedFile, Hunk

logger = logging.getLogger(__name__)


class DiffParsingError(Exception):
    """Exception raised when diff parsing fails."""
    pass


class DiffParser:
    """Parser for GitHub diff content with comprehensive error handling."""
    def __init__(self):
        logger.debug("Initialized diff parser")
    
    def parse_diff(self, diff_content: str) -> List[PatchedFile]:
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
    
    def _parse_with_unidiff(self, diff_content: str) -> List[PatchedFile]:
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
                
            patched_files = []
            
            for i, patched_file in enumerate(patch_set):
                logger.debug(f"Processing patched file {i+1}: {patched_file.source_file} -> {patched_file.target_file}")

                if patched_file.is_removed_file: # 排除删除文件的情况
                    logger.debug(f"⚠️ Skipping removed file: {patched_file.source_file}")
                    continue
                
                if patched_file.is_binary_file: # 跳过二进制文件
                    logger.debug(f"⚠️ Skipping binary file: {patched_file.path}")
                    return None
                
                patched_files.append(patched_file)
                logger.debug(f"✅ Successfully parsed file: {patched_file.path}")
            
            logger.info(f"Unidiff parsing completed: {len(patched_files)} files processed, {len(patch_set) - len(patched_files)} skipped")
            return patched_files
            
        except Exception as e:
            logger.warning(f"Unidiff parsing error: {str(e)}")
            logger.debug(f"Diff content preview: {diff_content[:1000]}...")
            raise
    
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