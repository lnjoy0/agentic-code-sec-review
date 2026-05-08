import tree_sitter_python as tspython
from tree_sitter import Parser, Node
from typing import Dict, Any, Tuple
import os
import logging

logger = logging.getLogger(__name__)

def get_target_node(file_path: str, start_point: Tuple[int, int], end_point: Tuple[int, int]) -> Tuple[Node, bytes]:
    """
    根据起止坐标精准定位目标节点。
    - file_path: 目标文件路径
    - start_point: (start_row, start_column)
    - end_point: (end_row, end_column)
    """

    ext = os.path.splitext(file_path)[1].lower()
    if ext != '.py':
        logger.error(f"错误：不支持的文件类型后缀 {ext}，当前只支持 Python 文件分析")
        return None
    
    parser = Parser(tspython.language())

    try:
        with open(file_path, "rb") as f:
            source_bytes = f.read()
    except FileNotFoundError:
        logger.error(f"错误：找不到文件 {file_path}")
        return None

    # 解析生成 AST
    tree = parser.parse(source_bytes)

    # 根据坐标精准定位目标节点
    target_node = tree.root_node.descendant_for_point_range(start_point, end_point)
    if target_node is None:
        logger.error(f"错误：在文件 {file_path} 中未找到有效节点")
        return None
    
    return target_node, source_bytes

def get_node_signature(node) -> str:
    """提取函数或类的签名部分（包括装饰器和定义行）"""

    actual_def_node = node
    if node.type == 'decorated_definition':
        for child in node.children:
            if child.type in ('function_definition', 'class_definition'):
                actual_def_node = child
                break

    # 找到定义节点的主体
    block = next((child for child in actual_def_node.children if child.type == 'block'), None)
    
    if block:
        src_bytes = node.text
        
        # 计算签名部分的字节长度
        signature_end_byte = block.start_byte - node.start_byte # start_byte 是节点在整个源文件中的起始字节位置
        return src_bytes[:signature_end_byte].decode('utf-8').strip()
    
    return ""

def get_snippet_and_context(file_path: str, start_point: tuple, end_point: tuple, 
                            min_lines: int, max_lines: int) -> Tuple[str, str]:
    """根据起止坐标提取代码片段及其上下文"""

    snippet_node, source_bytes = get_target_node(file_path, start_point, end_point)
    if not snippet_node:
        return "", ""

    snippet = snippet_node.text.decode('utf-8')
    source_lines = source_bytes.decode('utf-8').splitlines()

    context = snippet  # 默认上下文为代码片段本身
    current = snippet_node

    while current is not None:
        if current.type in ('class_definition', 'function_definition'):
            if current.parent is not None and current.parent.type == 'decorated_definition':
                candidate_node = current.parent # 包含装饰器
            else:
                candidate_node = current
            
            candidate_text = candidate_node.text.decode('utf-8')
            candidate_line_count = candidate_text.count('\n') + 1

            # 如果当前候选节点的行数超过 max_lines，触发截断策略，从 snippet 的起止行向外扩展
            # 直到达到 max_lines 或者到达候选节点的边界
            if candidate_line_count > max_lines:
                signature = get_node_signature(snippet_node)
                sig_lines = signature.count('\n') + 1 # 签名行数

                snippet_start_line = snippet_node.start_point[0]
                snippet_end_line = snippet_node.end_point[0]
                snip_lines = snippet_end_line - snippet_start_line + 1 # snippet 行数
                
                remaining_quota = max_lines - sig_lines - snip_lines - 2 # 可拓展的行数
                half_window = remaining_quota // 2

                # max 和 min 确保窗口不超过候选节点的范围
                win_start = max(candidate_node.start_point[0] + sig_lines, snippet_start_line - half_window)
                win_end = min(candidate_node.end_point[0], snippet_end_line + half_window)

                window_content = "\n".join(source_lines[win_start : win_end + 1])
                context = f"{signature}\n# ... [Omitted]\n{window_content}\n# ... [Omitted]" # 在前面拼接上签名
                break
                
            context = candidate_text
            
            # 如果当前候选节点行数已经满足最小行数要求，则停止继续向上寻找
            if candidate_line_count >= min_lines:
                break 

        # 继续向上寻找父节点
        current = current.parent
    
    return snippet, context