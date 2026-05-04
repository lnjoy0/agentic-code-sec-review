import logging
from langchain_core.runnables import RunnableConfig
from typing import Dict, Any, List
import json

from scanners import HeuristicScanner
from core.data_models import AuditState, ReviewComment


logger = logging.getLogger(__name__)


async def heuristic_scanner_node(state: AuditState, config: RunnableConfig) -> Dict[str, Any]:
    """启发式工具扫描器节点"""
    logger.info("[Node] 运行启发式扫描器 (Semgrep, Gitleaks, Trivy)...")

    scanner_config = config['configurable'].get('scanner_config')
    patched_files = state['patched_files']

    heuristic_scanner = HeuristicScanner(scanner_config)
    heuristic_report = await heuristic_scanner.get_report(patched_files)

    return {'scanner_reports': heuristic_report}


def get_comments_node(state: AuditState, config: RunnableConfig) -> List[ReviewComment]:
    """生成评论内容节点"""
    logger.info("=== 所有专家研判完毕，汇总结果 ===")

    results = state['refined_results']
    patched_files = state['patched_files']

    comments = []
    for tool, tool_results in results.items():                        
        comment = ReviewComment(
            body=json.dumps(tool_results[:100], indent=4),
            path=patched_files[0].path,
            position=1
        )
        comments.append(comment)
    
    return {'final_comment': comments}