import logging
import collections
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node
from langchain_core.tools import StructuredTool
from langchain_core.runnables import RunnableConfig


logger = logging.getLogger(__name__)


class CodeRetriever:
    """使用 ripgrep 和 tree-sitter 实现的代码检索器"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve() # 工作区的绝对路径
        if not self.repo_path.exists():
            raise ValueError(f"仓库路径不存在: {self.repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Error: 路径 {self.repo_path} 不是一个目录。")
            
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)

    async def _rg_filter(self, params: List[str]) -> List[Path]:
        """使用 ripgrep 过滤文件"""
        cmd = [
            "rg", "-l", 
            *params, 
            "-g", "*.py", 
            str(self.repo_path)
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            stdout_bytes = stdout.decode('utf-8', errors='replace')
            
            if not stdout_bytes:
                return []
            
            files = stdout_bytes.strip().split('\n')
            return [Path(f) for f in files if f]
        
        except Exception as e:
            logger.error(f"ripgrep 调用中出错: {e}")
            return []

    async def _find_definition_files(self, target_name: str) -> List[Path]:
        """查找包含目标定义的所有文件路径"""
        regexp = [
            "-e", f"def\\s+{target_name}\\b",
            "-e", f"class\\s+{target_name}\\b"
        ]
        files = self._rg_filter(regexp)
        if not files:
            logger.info(f"📄 未找到 `{target_name}` 的任何定义文件。")
            return []
        
        return files

    async def _find_definition_in_file(self, target_name:str, abs_file_path: Path) -> Dict[str, Any]:
        """在特定文件中查找目标的定义节点"""
        try:
            def _read_file_safely():
                if not abs_file_path.exists():
                    return None
                with open(abs_file_path, 'rb') as f:
                    return f.read()

            source_code = await asyncio.to_thread(_read_file_safely)
            
            rel_file_path = abs_file_path.relative_to(self.repo_path) # 相对路径

            if source_code is None:
                logger.error(f"目标文件不存在 `{rel_file_path}`")
                return {}
            
            tree = await asyncio.to_thread(self.parser.parse, source_code)

            def traverse(node: Node):
                if node.type in ('class_definition', 'function_definition'):
                    node_name = node.child_by_field_name('name')
                    if node_name and source_code[node_name.start_byte:node_name.end_byte].decode('utf-8') == target_name:

                        # 捕获装饰器
                        extract_node = node
                        if node.parent and node.parent.type == 'decorated_definition':
                            extract_node = node.parent

                        return {
                            "file_path": str(rel_file_path),
                            "extract_node": extract_node, # 包含装饰器的节点
                            "core_node": node,            # def 或 class 本身的节点
                            "source_code": source_code,
                            "type": "class" if node.type == "class_definition" else "function"
                        }
                for child in node.children:
                    traverse(child)

            traverse(tree.root_node)
            logger.warning(f"在 {rel_file_path} 未找到 {target_name} 的定义节点")
            return {}
        except Exception as e:
            logger.error(f"解析文件 {rel_file_path} 失败: {e}")
            return {}

    async def find_definition(
        self, 
        target_name: str, 
        max_lines: int = 200,
        config: RunnableConfig = None
    ) -> str:
        """
        基于 AST 全局检索目标类 (Class) 或函数 (Function) 的源代码定义。
        
        【何时使用】：当遇到未知函数/类，需深挖其内部实现以研判漏洞时调用（如：验证自定义污点清洗机制、审查加解密与脱敏封装、确认鉴权装饰器或中间件底层逻辑等）。
        
        Args:
            target_name (str): 目标函数名或类名（需提供精确名称，勿带括号或模块前缀，如 "sanitize_input"）。
            max_lines (int, optional): 读取定义的最大行数，默认 200。该值只能小于或等于200。

        Returns:
            str: 包含定义所在路径、行号与代码片段的 Markdown 文本。
        """
        nodes_info = []

        candidate_files = await self._find_definition_files(target_name)
        for abs_file_path in candidate_files:
            nd_info = await self._find_definition_in_file(target_name, abs_file_path)
            if nd_info:
                nodes_info.append(nd_info)

        if not nodes_info:
            return f"📄 未找到 `{target_name}` 的任何定义。"

        config_max_lines = config['configurable'].get('context_config').context_max_lines
        max_lines = max(0, min(max_lines, config_max_lines))

        # 计算动态行数限制
        n_defs = len(nodes_info)
        line_limit_per_def = max(1, max_lines // n_defs)
        
        # 拼接排版
        output_lines = [
            f"### 🎯 定义查找结果: `{target_name}`",
            f"> **总计找到**: {n_defs} 处定义",
            "---"
        ]

        for info in nodes_info:
            extract_node = info['extract_node']
            code_str = info['source_code'][extract_node.start_byte:extract_node.end_byte].decode('utf-8')
            lines = code_str.split('\n')
            
            start_line = extract_node.start_point[0] + 1 # tree-sitter 的行号从 0 开始索引，转为 1 开始
            end_line = extract_node.end_point[0] + 1
            file_path = info['file_path']
            def_type = info['type']
            
            # 判断是否需要截断
            is_truncated = len(lines) > line_limit_per_def
            if is_truncated:
                truncated_lines = lines[:line_limit_per_def]
                pure_code = '\n'.join(truncated_lines)
                next_start_line = start_line + line_limit_per_def
                current_end = start_line + line_limit_per_def - 1
            else:
                pure_code = code_str
                current_end = end_line

            type_label = "类 (Class)" if def_type == "class" else "函数 (Function)"
            
            output_lines.append(f"\n#### 📄 [{type_label}] in `{file_path}`")
            output_lines.append(f"**Lines {start_line}-{current_end}** (完整定义至第 {end_line} 行):")
            output_lines.append("```python")
            output_lines.append(pure_code)
            output_lines.append("```")

            # 将系统级指令（截断提示）放在代码块外部，防止 LLM 产生“代码幻觉”
            if is_truncated:
                output_lines.append(
                    f"💡 **片段截断提示**: 代码已截断至前 {line_limit_per_def} 行。\n"
                    f"若需继续查看后续定义，请使用 `fetch_definition_chunk` 工具，并传入参数:\n"
                    f"> `file_path='{file_path}'`\n"
                    f"> `target_name='{target_name}'`\n"
                    f"> `start_line={next_start_line}`"
                )
            else:
                output_lines.append(f"*(✅ 此为该定义的完整代码)*")

        return "\n".join(output_lines)

    async def fetch_definition_chunk(
        self, 
        target_name: str, 
        file_path: str, 
        start_line: int,
        max_lines: int = 200,
        config: RunnableConfig = None
    ) -> str:
        """
        分页拉取长函数或类定义的后续代码片段。
        
        【何时使用】：当前置查询出现“片段截断提示”，且**已加载的代码不足以支撑你得出最终安全结论，需要查看后续代码时**调用。若已加载的部分已提供决定性的漏洞证据或确凿的安全防御证明，请主动停止拉取以节省上下文。
        
        Args:
            target_name (str): 目标函数名或类名（需与截断提示保持一致）。
            file_path (str): 目标文件路径（需与截断提示保持一致）。
            start_line (int): 继续阅读的起始行号（严格填入截断提示中给出的 `next_start_line`）。
            max_lines (int, optional): 读取后续定义的最大行数，默认 200。该值只能小于或等于200。

        Returns:
            str: 指定行号后续的代码片段。
        """
        abs_path = self.repo_path / file_path

        def _read_file_safely():
            if not abs_path.exists():
                return None
            with open(abs_path, 'r', encoding='utf-8') as f:
                return f.read().split('\n')

        all_lines = await asyncio.to_thread(_read_file_safely)
        
        if all_lines is None:
            return f"❌ 错误: 文件不存在 `{file_path}`"
        
        target_info = await self._find_definition_in_file(target_name, abs_path)
        if not target_info:
            return f"❌ 错误: 未能在 `{file_path}` 中找到覆盖行号 {start_line} 的 `{target_name}` 的定义。"
            
        def_end_line = target_info['extract_node'].end_point[0] + 1
       
        config_max_lines = config['configurable'].get('context_config').context_max_lines
        max_lines = max(0, min(max_lines, config_max_lines))

        idx_start = start_line - 1
        idx_end = min(idx_start + max_lines, def_end_line) # 到定义结束或者再次达到行数限制

        chunk_lines = all_lines[idx_start:idx_end]
        is_ended = idx_end >= def_end_line

        pure_code = '\n'.join(chunk_lines)

        # 排版拼接
        output_lines = [
            f"### 📖 代码片段: `{target_name}` (Lines {start_line}-{idx_end})",
            f"> **文件路径**: `{file_path}`",
            "```python",
            pure_code,
            "```"
        ]

        # 底部操作指引
        if not is_ended:
            next_start_line = start_line + max_lines
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **片段截断提示**: 当前展示至第 {idx_end} 行（完整定义至第 {def_end_line} 行结束）。\n"
                f"若需继续阅读后续代码，请再次调用此工具并传入参数 `start_line={next_start_line}`。"
            )
        else:
            output_lines.append("\n*(✅ 此处为该定义的结尾)*")
            
        return "\n".join(output_lines)
    
    def _iter_identifier_usages(self, source_code: bytes, root_node: Node, target_name: str):
        """
        通用的 AST 遍历生成器，寻找目标标识符的所有非定义调用。
        每次找到匹配项时，yield: (当前标识符节点, 当前作用域节点, 所在完整语句的节点)
        """
        def traverse(node: Node, current_scope: Optional[Node]):
            if node.type in ('class_definition', 'function_definition'):
                current_scope = node
            
            if node.type == 'identifier':
                name = source_code[node.start_byte:node.end_byte].decode('utf-8')
                if name == target_name:
                    # 排除类定义或函数定义本身的名称
                    is_definition_name = False
                    if node.parent and node.parent.type in ('class_definition', 'function_definition'):
                        if node.parent.child_by_field_name('name') == node:
                            is_definition_name = True
                    
                    if not is_definition_name:
                        track_node = node
                        # 查完整语句
                        while track_node and track_node.parent and track_node.parent.type not in ('block', 'module'):
                            track_node = track_node.parent
                        snippet_node = track_node if track_node else node
                        
                        # 把这三个关键节点抛出给外层使用
                        yield node, current_scope, snippet_node

            # 递归遍历子节点
            for child in node.children:
                yield from traverse(child, current_scope)

        # 从根节点启动并抛出结果
        yield from traverse(root_node, None)

    def _extract_scope_info(self, current_scope: Optional[Node], source_code: bytes) -> tuple[str, str]:
        """
        提取当前作用域的名称和签名。
        返回: (scope_name, signature)
        """
        scope_name = "<module_level>"
        signature = "Global Scope"

        if current_scope:
            # 提取作用域名称
            scope_name_node = current_scope.child_by_field_name('name')
            if scope_name_node:
                scope_name = source_code[scope_name_node.start_byte:scope_name_node.end_byte].decode('utf-8')

            # 提取签名（截取到 body 开始前）
            body_node = current_scope.child_by_field_name('body')
            if body_node:
                extract_node = current_scope
                if current_scope.parent and current_scope.parent.type == 'decorated_definition':
                    extract_node = current_scope.parent
                signature = source_code[extract_node.start_byte:body_node.start_byte].decode('utf-8').strip()

        return scope_name, signature

    def _truncate_snippet(
        self, 
        raw_snippet: str, 
        node_line: int, 
        snippet_start_line: int, 
        max_lines: int = 10
    ) -> str:
        """
        截断过长的代码片段，仅保留目标节点前后各三行。
        """
        lines = raw_snippet.split('\n')
        if len(lines) <= max_lines: # 行数超过 max_lines 时进行截断
            return raw_snippet

        rel_idx = node_line - snippet_start_line
        start_idx = max(0, rel_idx - 3)
        end_idx = min(len(lines), rel_idx + 4)
        
        truncated_lines = []
        if start_idx > 0: 
            truncated_lines.append("# ... [上文已截断]")
        truncated_lines.extend(lines[start_idx:end_idx])
        if end_idx < len(lines): 
            truncated_lines.append("# ... [下文已截断]")
            
        return '\n'.join(truncated_lines)

    async def find_references(self, target_name: str) -> str:
        """
        全局检索目标函数、类或变量的所有调用与引用记录（Cross-Reference）。
        
        【何时使用】：当需要进行正/逆向污点追踪（验证 Source 是否触达危险 Sink）、评估某个缺陷组件/弱加密算法的全局影响面，或审查自定义鉴权/脱敏规则在系统中的覆盖率时调用。
        
        Args:
            target_name (str): 需检索的目标标识符名称（需精确匹配，勿带括号或参数，如 "eval", "sanitize_input", "AES"）。

        Returns:
            str: 按文件分组的引用列表，包含调用所在行号、所属作用域/函数签名（Scope Signature）以及目标前后的精简上下文代码片段。
            💡 提示：为防上下文溢出，返回的片段已裁剪为目标前后的核心行。若需深挖某次特定调用的完整执行链，请利用此处获取的文件路径与行号，配合相关代码读取工具进一步探查。
        """
        regexp = [
            "-e", f"\\b{target_name}\\b"
        ]
        candidate_files = await self._rg_filter(regexp)
        if not candidate_files:
            return f"📄 未找到 `{target_name}` 的任何调用或引用记录。"

        results = []
        for abs_file_path in candidate_files:
            try:

                def _read_file_safely():
                    if not abs_file_path.exists():
                        return None
                    with open(abs_file_path, 'rb') as f:
                        return f.read()

                source_code = await asyncio.to_thread(_read_file_safely)
                
                rel_file_path = abs_file_path.relative_to(self.repo_path) # 相对路径

                if source_code is None:
                    return f"❌ 错误: 文件不存在 `{rel_file_path}`"
                
                tree = await asyncio.to_thread(self.parser.parse, source_code)
                
                seen_snippet_starts = set() # 对同一行的查询结果去重

                for node, current_scope, snippet_node in self._iter_identifier_usages(source_code, tree.root_node, target_name):
                    snippet_start = snippet_node.start_byte
                    snippet_end = snippet_node.end_byte
                                
                    # 如果引用发生在函数/类定义的头部（例如参数类型提示、返回类型、继承、装饰器中），则 snippet 只保留头部
                    if snippet_node.type in ('function_definition', 'class_definition', 'decorated_definition'):
                        body_node = None
                        if snippet_node.type == 'decorated_definition':
                            for child in snippet_node.children:
                                if child.type in ('function_definition', 'class_definition'):
                                    body_node = child.child_by_field_name('body')
                                    break
                        else:
                            body_node = snippet_node.child_by_field_name('body')
                            
                        if body_node:
                            snippet_end = body_node.start_byte # 截断到 body 开始前（即保留到冒号为止）

                    if snippet_start not in seen_snippet_starts: # 去重
                        seen_snippet_starts.add(snippet_start)
                        raw_snippet = source_code[snippet_start:snippet_end].decode('utf-8').strip()
                        
                        # 提取 scope_name 和 signature
                        scope_name, signature = self._extract_scope_info(current_scope, source_code)

                        # 如果 snippet 超过 10 行，则仅保留 target 所在行的上下各三行
                        snippet_code = self._truncate_snippet(
                            raw_snippet, 
                            node.start_point[0], 
                            snippet_node.start_point[0]
                        )
                        
                        results.append({
                            "file_path": str(rel_file_path),
                            "line_number": node.start_point[0] + 1,
                            "scope_name": scope_name,
                            "signature": signature,
                            "snippet": snippet_code,
                            "snippet_start": snippet_node.start_byte,
                            "snippet_end": snippet_node.end_byte
                        })

            except Exception as e:
                logger.error(f"解析文件 {rel_file_path} 失败: {e}")

        if not results:
            return f"📄 未找到 `{target_name}` 的任何有效调用。"

        # 按文件路径和行号排序
        results.sort(key=lambda x: (x['file_path'], x['line_number']))

        # 按文件对引用进行分组
        grouped_results = collections.defaultdict(list)
        for res in results:
            grouped_results[res['file_path']].append(res)

        # 排版拼接
        output_lines = [
            f"### 🔗 引用查找结果: `{target_name}`",
            f"> **总计调用/引用次数**: {len(results)} 处",
            "---"
        ]

        for rel_file_path, refs in grouped_results.items(): # 分文件进行渲染
            output_lines.append(f"\n#### 📄 `{rel_file_path}`")
            for ref in refs:
                # 标题标明行号和作用域
                scope_display = f"def {ref['scope_name']}" if ref['scope_name'] != "<module_level>" else "Global Scope"
                output_lines.append(f"**Line {ref['line_number']}** in `{scope_display}`:")
                
                # 如果有具体的函数签名（不是全局作用域），可以折叠或引用展示，辅助 LLM 理解上下文约束
                if ref['signature'] != "Global Scope":
                    # 将签名的换行进行缩进处理，使其在 blockquote 中显示更好看
                    formatted_sig = ref['signature'].replace('\n', '\n> ')
                    output_lines.append(f"> *Signature*: \n> {formatted_sig}")
                
                output_lines.append("```python")
                output_lines.append(ref['snippet'])
                output_lines.append("```")

        return "\n".join(output_lines)
    
    def _determine_access_type(self, n: Node) -> str:
        """通过向上回溯 AST 树，判断变量是被读取还是被写入"""
        p = n.parent
        while p and p.type not in ('block', 'module'):
            # 赋值与增强赋值 (e.g. a = 1, a += 1)
            if p.type in ('assignment', 'augmented_assignment'):
                left = p.child_by_field_name('left')
                # 只要在左侧表达式内部，就算写入
                if left and n.start_byte >= left.start_byte and n.end_byte <= left.end_byte:
                    return "Write (Assignment)"
            
            # For 循环的迭代变量绑定 (e.g. for a in items:)
            elif p.type == 'for_statement':
                left = p.child_by_field_name('left')
                if left and n.start_byte >= left.start_byte and n.end_byte <= left.end_byte:
                    return "Write (For-Loop Binding)"
            
            # 函数参数定义 (e.g. def foo(a=1):)
            elif p.type in ('parameters', 'typed_parameter', 'default_parameter', 'lambda_parameters'):
                return "Write (Parameter Definition)"
            
            # Context/Exception 别名绑定 (e.g. with open() as a:, except Exception as a:)
            elif p.type == 'as_pattern':
                alias = p.child_by_field_name('alias')
                if alias and n.start_byte >= alias.start_byte and n.end_byte <= alias.end_byte:
                    return "Write (Alias Binding)"
            
            # 全局或非局部声明
            elif p.type in ('global_statement', 'nonlocal_statement'):
                return "Declaration"
                
            p = p.parent
            
        return "Read (Usage)"

    async def track_variable_data_flow(
        self, 
        target_variable: str, 
        file_path: str,
        start_line: int = 1,
        detail_limit: int = 20,
        unseen_limit: int = 30
    ) -> str:
        """
        在指定文件内追踪特定变量的数据流，还原其赋值 (Write) 与调用 (Read) 的完整生命周期。
        
        【何时使用】：必须用于局部污点分析与状态追踪。例如：
        1. [污点追踪] 观察不可信输入 (Source) 在流转过程中是否被过滤，以及最终是否触达危险执行点 (Sink)。
        2. [资产审查] 追踪敏感变量（如 `password`, `api_key`）是否在后续逻辑中被违规打印至日志或未加密外发。
        3. [逻辑与状态] 追踪权限标识（如 `is_admin`）或核心业务变量是否在执行流中遭到意外篡改。
        
        Args:
            target_variable (str): 需追踪的变量名（需精确匹配，勿带修饰符，如 "user_input"）。
            file_path (str): 目标代码文件的相对路径。
            start_line (int, optional): 起始追踪行号（默认 1）。用于遇到截断时继续拉取后续记录。

        Returns:
            str: 包含读写类型 `[Read]/[Write]`、所在作用域及代码片段的 Markdown 记录流。
            ⚠️ 分页策略：为防上下文溢出，返回结果由前部的“详细片段”与后部的“单行摘要”组成。若详细区尚未展现变量的最终归宿（Sink），且摘要区暗示后续有重要操作，请严格按底部提示更新 `start_line` 继续拉取；若漏洞已被证实或证伪，请立即停止以节省 Token。
        """
        abs_path = self.repo_path / file_path

        def _read_file_safely():
            if not abs_path.exists():
                return None
            with open(abs_path, 'rb') as f:
                return f.read()

        source_code = await asyncio.to_thread(_read_file_safely)
        
        if source_code is None:
            return f"❌ 错误: 文件不存在 `{file_path}`"

        all_records = []
        try:            
            tree = await asyncio.to_thread(self.parser.parse, source_code)
            seen_snippets = set()

            for node, current_scope, snippet_node in self._iter_identifier_usages(source_code, tree.root_node, target_variable):
                access_type = self._determine_access_type(node)
                dedup_key = (snippet_node.start_byte, access_type)

                if dedup_key not in seen_snippets: # 去重
                    seen_snippets.add(dedup_key)

                    # 提取 scope_name
                    scope_name, _ = self._extract_scope_info(current_scope, source_code)

                    # 将原始信息存入列表，留待后续截断和格式化
                    all_records.append({
                        "line_number": node.start_point[0] + 1,
                        "scope_name": scope_name,
                        "access_type": access_type,
                        "snippet_start": snippet_node.start_byte,
                        "snippet_end": snippet_node.end_byte,
                        "node_start_line": node.start_point[0],
                        "snippet_start_line": snippet_node.start_point[0]
                    })

        except Exception as e:
            logger.error(f"解析文件 {abs_path} 失败: {e}")
            return f"❌ 解析失败: `{str(e)}`"

        if not all_records:
            return f"📄 在 `{file_path}` 中未找到变量 `{target_variable}` 的引用。"

        # 过滤掉 start_line 之前的记录
        all_records.sort(key=lambda x: x['line_number'])
        filtered_records = [r for r in all_records if r['line_number'] >= start_line]
        
        if not filtered_records:
            return f"📄 从第 {start_line} 行开始，未发现变量 `{target_variable}` 的后续引用。"

        # 排版拼接
        output_lines = [
            f"### 🔍 数据流追踪: `{target_variable}` in `{file_path}`",
            f"> **总计引用**: {len(all_records)} 处",
            "---"
        ]
        
        summary_outlines = []
        has_more = len(filtered_records) > detail_limit
        next_start = filtered_records[detail_limit]['line_number'] if has_more else None

        # 只提供前 detail_limit 条记录的详细代码
        for i, record in enumerate(filtered_records):
            if i < detail_limit:
                raw_snippet = source_code[record['snippet_start']:record['snippet_end']].decode('utf-8').strip()
                # 代码截断
                snippet_code = self._truncate_snippet(
                    raw_snippet, 
                    record['node_start_line'], 
                    record['snippet_start_line']
                )

                # 渲染详细代码片段
                output_lines.append(f"**[{record['access_type']}]** Line {record['line_number']} in `def {record['scope_name']}`:")
                output_lines.append("```python")
                output_lines.append(snippet_code)
                output_lines.append("```")
            else:
                # 记录超出部分的摘要
                summary_outlines.append(f"- Line {record['line_number']} `[{record['access_type']}]` in `{record['scope_name']}`")

        # 后续 unseen_limit 条记录仅给出摘要
        if summary_outlines:
            output_lines.append("\n### 📌 后续引用摘要 (未显示详情)")
            output_lines.extend(summary_outlines[:unseen_limit])
            if len(summary_outlines) > unseen_limit:
                output_lines.append("- ... *(剩余摘要已隐藏)*")

        # 底部操作指引 (Prompt 强化)
        if has_more:
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **提示**: 仍有 {len(filtered_records) - detail_limit} 个引用未显示详情。若需查看详细代码，"
                f"请重新调用此工具并传入 `start_line={next_start}`。"
            )

        return "\n".join(output_lines)
        
    def _point_check(
        self, 
        source_lines: List[str], 
        point: Tuple[int, int] # 0-indexed
    ) -> Tuple[int, int]:
        """坐标值检查"""
        total_lines = len(source_lines)

        # 边界检查
        point_line = max(0, min(total_lines - 1, point[0]))

        line_text = source_lines[point_line]
        line_text_cols = len(line_text)
        point_col = max(0, min(line_text_cols, point[1])) # tree-sitter中，列的最大边界是开区间坐标
        
        # 如果列号位于前导空格中，将其修改为第一个非空字符的索引
        lspaces = line_text_cols - len(line_text.lstrip()) # 该行左侧的空白符个数
        point_col = max(lspaces, point_col)
        
        return (point_line, point_col)

    async def core_get_code_context(
        self, 
        file_path: str, # 文件相对路径
        start_point: Tuple[int, int], # 1-indexed
        end_point: Tuple[int, int],
        max_lines: int = 200,
        min_lines: int = 0
    ) -> Tuple[str, Tuple]:
        """
        根据起止坐标提取目标代码片段的上下文。
        如果上下文行数大于 max_lines，则将其截断。
        如果上下文行数小于 min_lines，则进入上一级节点（类或函数）中提取上下文。
        """
        abs_path = self.repo_path / file_path
        if abs_path.suffix != '.py':
            raise ValueError(f"不支持的文件类型后缀 {abs_path.suffix}，当前只支持 Python 文件分析")

        try:
            async def _read_file():
                with open(abs_path, "rb") as f:
                    return f.read()
            source_bytes = await _read_file()
        except FileNotFoundError:
            raise FileNotFoundError(f"找不到文件 {file_path}")
        
        tree = await asyncio.to_thread(self.parser.parse, source_bytes) # 将 tree-sitter 解析放入线程池，否则会阻塞异步协程
        source_lines = source_bytes.decode('utf-8').splitlines()

        # 将编辑器坐标转成tree-sitter坐标（0-indexed），并进行坐标值检查
        start_point_ts = self._point_check(source_lines, (start_point[0] - 1, start_point[1] - 1))
        end_point_ts = self._point_check(source_lines, (end_point[0] - 1, end_point[1] - 1))

        signature_lines = []
        context_lines = []

        # 获取目标代码片段所在的最小节点，作为锚点
        anchor_node = tree.root_node.descendant_for_point_range(start_point_ts, end_point_ts)
        if anchor_node is None:
            raise RuntimeError(f"在文件 {file_path} 中未找到有效节点")

        start_row = anchor_node.start_point[0]
        end_row = anchor_node.end_point[0] + 1
        bound_start_row = start_row
        bound_end_row = end_row

        anchor_line_count = end_row - start_row

        # 从锚点开始向上层寻找函数/类定义节点、全局节点或根节点
        current_node = anchor_node
        while current_node is not None:
            is_def = current_node.type in ('class_definition', 'function_definition') # 类或函数的定义节点
            is_top_level = current_node.parent is not None and current_node.parent.type == 'module' # 全局位置的节点
            is_root = current_node.parent is None # 当前节点就是根节点

            # 如果不是我们关心的节点层级，继续向上寻找
            if not (is_def or is_top_level or is_root):
                current_node = current_node.parent
                continue

            # 确定完整的提取节点
            extract_node = current_node
            if is_def and current_node.parent is not None and current_node.parent.type == 'decorated_definition':
                extract_node = current_node.parent # 将装饰器加入要提取的上下文中

            start_row = extract_node.start_point[0]
            end_row = extract_node.end_point[0] + 1 # 右边界统一格式化为开区间坐标
            bound_start_row = start_row # 更新截断边界
            bound_end_row = end_row

            extract_line_count = end_row - start_row

            # 如果提取节点的行数超过 max_lines，触发滑动窗口截断
            if extract_line_count > max_lines:
                signature_start_row = None
                signature_end_row = None

                # 如果是函数或类，提取包含装饰器的 signature，然后将截断边界设为 body_node 的边界
                if is_def:
                    body_node = current_node.child_by_field_name('body')
                    if body_node:
                        signature_start_row = extract_node.start_point[0]
                        signature_end_row = body_node.start_point[0]
                        bound_start_row = body_node.start_point[0]
                        bound_end_row = body_node.end_point[0] + 1

                # 计算滑动窗口的起止索引，签名不参与总长度计算
                if max_lines > anchor_line_count:
                    remaining_line_count = max_lines - anchor_line_count
                    half_before = remaining_line_count // 2

                    # 从锚点开始拓展上下文行数到 max_lines
                    start_row = anchor_node.start_point[0] - half_before
                    end_row = anchor_node.end_point[0] + 1 + (remaining_line_count - half_before) # 开区间坐标
                else:
                    target_line_count = end_point_ts[0] - start_point_ts[0] + 1
                    remaining_line_count = max(0, max_lines - target_line_count)
                    half_before = remaining_line_count // 2

                    # 从目标代码片段开始拓展上下文行数到 max_lines
                    start_row = start_point_ts[0] - half_before
                    end_row = end_point_ts[0] + 1 + (remaining_line_count - half_before)

                # 触碰上边界时，窗口整体下移
                if start_row < bound_start_row:
                    end_row += (bound_start_row - start_row)
                    start_row = bound_start_row
                    
                # 触碰下边界时，窗口整体上移
                if end_row > bound_end_row:
                    start_row -= (end_row - bound_end_row)
                    end_row = bound_end_row
                    # 确保 start 不为负数
                    start_row = max(0, start_row)                    

                context_lines = source_lines[start_row : end_row]

                if signature_start_row is not None and signature_end_row is not None:
                    signature_lines = source_lines[signature_start_row : signature_end_row]
                
                break

            # 未超长的情况：直接采用提取节点的完整文本
            context_lines = source_lines[start_row : end_row]
            
            # 如果到达顶层，无论是否满足 min_lines 都必须停止
            if is_top_level or is_root:
                break

            # 如果满足最小行数要求，停止继续向上寻找
            if extract_line_count >= min_lines:
                break 

            current_node = current_node.parent

        # 拼接排版
        output_lines = [
            f"### 🎯 上下文提取: `{file_path}`",
            f"> **目标行**: {start_point[0]}-{end_point[0]} 行",
            f"> **文件总行数**: {len(source_lines)} 行 | **当前切片**: {start_row + 1}-{end_row} 行",
            f"```python"
        ]

        if signature_lines:
            for i, line in enumerate(signature_lines):
                current_line_num = signature_start_row + 1 + i
                prefix = "  "
                output_lines.append(f"{prefix} {current_line_num:4d} | {line}")

        if start_row > bound_start_row:
            output_lines.append("# ... [上下文已截断]")

        for i, line in enumerate(context_lines):
            current_line_num = start_row + 1 + i
        
            if current_line_num in range(start_point[0], end_point[0] + 1):
                prefix = "=>" # 给目标行打上 `=>` 箭头标记
            else:
                prefix = "  "

            output_lines.append(f"{prefix} {current_line_num:4d} | {line}")

        if end_row < bound_end_row:
            output_lines.append("# ... [上下文已截断]")

        output_lines.append("```")

        return '\n'.join(output_lines), (start_row + 1, end_row)

    async def get_code_context(
        self,
        file_path: str,
        target_line: int,
        max_lines: int = 200,
        config: RunnableConfig = None
    ) -> str:
        """
        基于 AST 智能提取指定代码行所在的完整逻辑块（函数或类）上下文。
        
        【何时使用】：当你已知潜在漏洞所在的具体行号（如扫描器告警给出的 Sink 触发点、引用查询定位到的特定调用），需要快速审视该行所处的整个局部作用域时调用。        
        
        Args:
            file_path (str): 目标代码文件的相对路径。
            target_line (int): 需重点分析的中心行号（返回的代码片段中将以 `=>` 明确高亮指示该行）。
            max_lines (int, optional): 允许返回的最大上下文行数，默认 200。该值只能小于或等于200。

        Returns:
            str: 带有行号标注的 Markdown 代码块。
        """
        config_max_lines = config['configurable'].get('context_config').context_max_lines
        max_lines = max(0, min(max_lines, config_max_lines))

        try:
            context, _, _ = await self.core_get_code_snippet_and_context(
                file_path, 
                (target_line, 1), 
                (target_line, 1), 
                max_lines
            )
        except Exception as e:
            return f"❌ 提取上下文失败：{e}"
        
        return context

    async def get_file_imports(self, file_path: str) -> str:
        """
        基于 AST 解析并提取目标 Python 文件的所有导入依赖 (Imports)，支持区分全局导入与局部 (函数内) 导入。
        
        【何时使用】：当需要快速评估代码文件的“能力边界”与依赖关系，而无需拉取全量长代码时调用。常用于：
        1. [基线与供应链] 验证扫描器告警的 CVE 漏洞组件、危险第三方包是否在该文件中被真实引入（判断漏洞可达性）。
        2. [资产与密码学] 快速摸排文件顶部是否引入了弱密码学库（如 `Crypto.Cipher.DES`）、不安全的序列化库（如 `pickle`）或伪随机数模块（如 `random`）。
        3. [逻辑与注入] 确认文件是否正确引入了必要的安全防御组件（如全局鉴权装饰器、防 SSRF 库 `advocate`、安全 XML 解析器 `defusedxml`）。
        
        Args:
            file_path (str): 目标 Python 文件的相对路径。

        Returns:
            str: 按作用域（全局 `<module_level>` 与局部 `def scope_name`）分组聚合的 import 语句 Markdown 列表。
        """
        abs_path = self.repo_path / file_path

        def _read_file_safely() -> Optional[bytes]:
            if not abs_path.exists():
                return None
            with open(abs_path, 'rb') as f:
                return f.read()
        source_code = await asyncio.to_thread(_read_file_safely)

        if source_code is None:
            return f"❌ 错误: 文件不存在 `{file_path}`"

        # 按照 scope_name 聚合 raw_code
        grouped_imports = collections.defaultdict(list)

        try:
            tree = await asyncio.to_thread(self.parser.parse, source_code)

            def traverse(node: Node, current_scope: str):
                # 记录作用域
                if node.type in ('class_definition', 'function_definition'):
                    scope_node = node.child_by_field_name('name')
                    if scope_node:
                        current_scope = source_code[scope_node.start_byte:scope_node.end_byte].decode('utf-8')

                if node.type in ('import_statement', 'import_from_statement'):
                    raw_code = source_code[node.start_byte:node.end_byte].decode('utf-8').strip()
                    grouped_imports[current_scope].append(raw_code)

                for child in node.children:
                    traverse(child, current_scope)

            # 从全局作用域开始遍历
            traverse(tree.root_node, "<module_level>")

        except Exception as e:
            logger.error(f"解析文件 {file_path} 导入信息失败: {e}")
            return f"❌ 解析失败: `{str(e)}`"

        if not grouped_imports:
            return f"📄 文件 `{file_path}` 中未发现任何 import 语句。"

        # 排版拼接
        output_lines = [f"### 📦 导入依赖摘要：`{file_path}`"]

        if "<module_level>" in grouped_imports: # 全局导入
            output_lines.append("\n **[Global Scope: `<module_level>`]**")
            output_lines.append("```python")
            output_lines.append("\n".join(grouped_imports["<module_level>"]))
            output_lines.append("```")

        for scope, codes in grouped_imports.items(): # 局部导入
            if scope == "<module_level>":
                continue
            
            output_lines.append(f"\n **[Local Scope: `def {scope}`]**")
            output_lines.append("```python")
            output_lines.append("\n".join(codes))
            output_lines.append("```")

        return "\n".join(output_lines)
    
    def as_tools(self) -> List:
        """将类方法包装为标准 LangChain 工具列表"""
        return [
            StructuredTool.from_function(func=self.find_definition, name="find_definition"),
            StructuredTool.from_function(func=self.fetch_definition_chunk, name="fetch_definition_chunk"),
            StructuredTool.from_function(func=self.find_references, name="find_references"),
            StructuredTool.from_function(func=self.track_variable_data_flow, name="track_variable_data_flow"),
            StructuredTool.from_function(func=self.get_code_context, name="get_code_context"),
            StructuredTool.from_function(func=self.get_file_imports, name="get_file_imports")
        ]