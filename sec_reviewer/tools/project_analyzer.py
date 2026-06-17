import logging
import collections
import asyncio
from pathlib import Path
from typing import List, Optional, Tuple
from langchain_core.tools import StructuredTool

from sec_reviewer.core.config import CodeRetrievalConfig


logger = logging.getLogger(__name__)


class ProjectAnalyzer:
    """提供项目与文件分析工具"""
    
    def __init__(self, repo_path: str, config: CodeRetrievalConfig):
        self.repo_path = Path(repo_path).resolve()
        self.config_max_lines = config.context_max_lines
        self.single_line_max_length = config.single_line_max_length

        if not self.repo_path.exists():
            raise ValueError(f"仓库路径不存在: {self.repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Error: 路径 {self.repo_path} 不是一个目录。")

    async def get_project_structure(
        self, 
        sub_dir: Optional[str] = None,
        max_depth: int = 1
    ) -> str:
        """
        获取代码仓库的宏观目录树结构（ASCII视图），每次调用只能查看两层目录，如需更多细节可以使用具体子目录名称再次调用。
        （为节省 token，该工具已过滤 .git 等构建目录，以及日志和文档文件）
        
        【何时使用】：当需要建立项目全局上下文、定位配置文件、寻找流量路由入口，或需确认特定文件是否属于测试/Mock目录时调用。
        
        Args:
            sub_dir (str, optional): 指定查看的子目录相对路径。如果指定，将以此子目录作为根节点向下生成树状图。
            max_depth (int, optional): 遍历最大深度，默认 1。该值只能为 1 或 2。
            
        Returns:
            str: 项目目录结构的树状字符串。
        """
        if sub_dir:
            target_path = (self.repo_path / sub_dir).resolve()
            repo_root = self.repo_path.resolve()
            
            # 安全校验：确保指定的路径没有通过 '../' 逃逸出仓库根目录
            if not str(target_path).startswith(str(repo_root)):
                return f"⚠️ 错误：指定的子目录 '{sub_dir}' 超出了仓库范围。"
            
            if not target_path.exists():
                return f"⚠️ 错误：找不到指定的子目录 '{sub_dir}'。"
            if not target_path.is_dir():
                return f"⚠️ 错误：'{sub_dir}' 不是一个有效的目录。"
        else:
            target_path = self.repo_path

        # 忽略的目录，用于节省 Token 和过滤无关安全审计的构建产物
        ignore_dirs = {
            '.git', '__pycache__', 'venv', '.venv', 'env', 
            '.idea', '.vscode', 'node_modules', 'dist', 'build'
        }

        # 忽略的日志与文档文件，用于节省token
        ignore_exts = {
            '.log', '.md', '.txt', '.pdf', '.doc', '.docx', 
            '.csv', '.xlsx', '.rst', '.out'
        }

        max_depth = max(0, min(max_depth, 2)) # 每次调用的最大深度不能超过 2，防止大项目中文件太多导致上下文爆炸

        def _build_tree_sync() -> str:
            def generate_tree(dir_path: Path, prefix: str = '', current_depth: int = 1) -> str:
                if current_depth > max_depth:
                    return prefix + "└── ...\n"

                try:
                    all_contents = list(dir_path.iterdir())
                    contents = []
                    for c in all_contents:
                        if c.name in ignore_dirs:
                            continue
                        if c.is_file() and c.suffix.lower() in ignore_exts:
                            continue

                        contents.append(c)

                    contents.sort(key=lambda x: (x.is_file(), x.name.lower()))
                except PermissionError:
                    return prefix + "└── ... (无权限访问)\n"

                tree_str = ""
                pointers = ['├── '] * (len(contents) - 1) + ['└── '] if contents else []

                for pointer, content in zip(pointers, contents):
                    is_dir_flag = content.is_dir()
                    suffix = '/' if is_dir_flag else ''
                    tree_str += prefix + pointer + content.name + suffix + '\n'
                    
                    if is_dir_flag:
                        extension = '│   ' if pointer == '├── ' else '    '
                        tree_str += generate_tree(content, prefix + extension, current_depth + 1)
                        
                return tree_str

            return generate_tree(target_path)

        tree_content = await asyncio.to_thread(_build_tree_sync) # 放入线程池，避免读写阻塞

        # 拼接排版
        display_name = f"{self.repo_path.name}/{sub_dir}" if sub_dir else self.repo_path.name
        output_lines = [
            f"### 📦 代码仓库目录树 (Root: {display_name}):",
            f"{target_path.name}/",
            tree_content
        ]
        return '\n'.join(output_lines)

    async def global_search(
        self, 
        pattern: str, 
        file_pattern: Optional[str] = None, 
        is_regex: bool = True,
        max_results: int = 30
    ) -> str:
        """
        基于 ripgrep 实现的文本与正则表达式检索工具，可在代码库中的任意文件中查询任意字符串。

        【何时使用】：当需要全局查找危险函数（如 eval, os.system）、定位硬编码秘钥/弱加密算法、追踪特定路由入口与鉴权装饰器、或检索特定配置项时调用；此外，也可用于非 python 的代码检索。
        
        Args:
            pattern (str): 目标检索字符串或正则表达式。
            file_pattern (str, optional): Glob风格的文件路径过滤器（如 '*.py', '*.html', '*config*', 'src/**/*.py'）。强烈建议在已知上下文时传入，以大幅减少无关噪音。
            is_regex (bool, optional): pattern 是否作为正则表达式解析。默认 True。提示：若检索包含代码符号的纯文本（如 `password = "123"`），建议设为 False 以避免正则语法错误。
            max_results (int, optional): 限制返回的最大匹配数量。默认 30。警告：为防止上下文溢出，非必要请勿调大此值。

        Returns:
            str: 包含匹配文件路径、行号及对应代码片段的 Markdown 文本。
        """
        # -n: 显示行号
        # --no-heading: 确保每行格式为 filepath:line:content
        cmd = ["rg", "-n", "--color=never", "--no-heading", "-M", "5000"]
        
        if not is_regex:
            cmd.append("-F") # 固定字符串匹配
            
        if file_pattern:
            cmd.extend(["-g", file_pattern])

        # 过滤压缩文件和文档文件
        cmd.extend(["-g", "!*.min.js", "-g", "!*.min.css", "-g", "!*min.map",
                    "-g", "!*.log", "-g", "!*.md"])

        cmd.extend(["-e", pattern, str(self.repo_path)])

        try:
            # 创建异步子进程
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # 解码输出 (由于 ripgrep 默认输出 utf-8)
            raw_output = stdout.decode('utf-8', errors='replace')
            error_output = stderr.decode('utf-8', errors='replace')

            # 处理返回码
            if process.returncode != 0:
                if process.returncode == 1: # ripgrep 返回 1 通常表示没有找到匹配项
                    filter_msg = f" (在 `{file_pattern}` 中)" if file_pattern else ""
                    return f"📄 未找到匹配 `{pattern}` 的搜索结果{filter_msg}。"
                else:
                    logger.error(f"ripgrep 执行出错: {error_output}")
                    return f"❌ 搜索失败: `{error_output.strip()}`"

        except Exception as e:
            logger.error(f"启动 ripgrep 进程异常: {str(e)}")
            return f"❌ 启动搜索进程失败: `{str(e)}`"

        # 按文件分组
        matches_by_file = collections.defaultdict(list)
        total_matches = 0

        for line in raw_output.splitlines():
            if not line.strip():
                continue

            if "[Omitted long matching line]" in line:
                line = line.replace("[Omitted long matching line]", " ... [底层文件单行极长，无业务阅读价值，已被系统级强制忽略]")
                
            # 解析格式: filepath:line_number:content
            parts = line.split(":", 2)
            if len(parts) >= 3:
                abs_file_path, line_num, content = parts[0], parts[1], parts[2]
                
                # 防止单行文本超长（例如 .min.js 等压缩文件）造成 LLM 上下文爆炸
                if len(content) > self.single_line_max_length:
                    # 如果是普通文本搜索，尝试将关键字居中截取，保留有意义的上下文
                    if not is_regex and pattern in content:
                        idx = content.find(pattern)
                        start = max(0, idx - (self.single_line_max_length // 2))
                        end = min(len(content), idx + (self.single_line_max_length // 2))
                        prefix = "..." if start > 0 else ""
                        suffix = "..." if end < len(content) else ""
                        content = f"{prefix}{content[start:end]}{suffix} [单行过长已截断]"
                    else:
                        # 正则搜索或未找到精确位置时，直接截断头部
                        content = content[:self.single_line_max_length] + " ... [单行过长已截断]"

                # 转为相对路径，使输出更简短
                try:
                    from pathlib import Path
                    rel_path = str(Path(abs_file_path).relative_to(self.repo_path))
                except ValueError:
                    rel_path = abs_file_path
                    
                matches_by_file[rel_path].append((line_num, content))
                total_matches += 1

        # 拼接排版
        output_lines = [
            f"### 🔎 全局搜索结果: `{pattern}`",
            f"> **总计匹配**: {total_matches} 处" + (f" (已截断展示前 {max_results} 处)" if total_matches > max_results else ""),
        ]
        if file_pattern:
            output_lines.append(f"> **文件过滤**: `{file_pattern}`")
        output_lines.append("---")

        displayed_matches = 0
        is_truncated = False

        for rel_path, lines in matches_by_file.items():
            if displayed_matches >= max_results:
                is_truncated = True
                break
                
            output_lines.append(f"\n#### 📄 `{rel_path}`")
            output_lines.append("```python") # 泛用高亮
            for line_num, content in lines:
                if displayed_matches >= max_results:
                    output_lines.append("# ... [后续匹配已截断]")
                    is_truncated = True
                    break
                output_lines.append(f"{line_num}: {content.strip()}")
                displayed_matches += 1
            output_lines.append("```")

        # 底部操作指引
        output_lines.append("\n---")
        if is_truncated:
            output_lines.append(
                f"💡 **提示**: 搜索结果过多 (共 {total_matches} 处)，为保护上下文已截断。\n"
                f"**下一步建议**:\n"
                f"1. 如果已显示内容中没有想要的搜索结果，可以调整以下参数，重新调用该工具。\n"
                f"  1. 增加 `file_pattern` (如 `*.py`, `src/api/*`) 以缩小搜索范围。\n"
                f"  2. 使用更具体的正则表达式 (如增加前后缀匹配)。\n"
                f"2. 如果想查看某个搜索结果的上下文，可以根据目标文件类型选择以下两个工具，并传入目标文件路径与目标行号。\n"
                f"  1. 对于 `.py` 文件，使用 `get_code_context` 工具。\n"
                f"  2. 对于其他文件，使用 `read_file_context` 工具。"
            )
        else:
            output_lines.append(
            f"💡 **下一步建议**:\n"
            f"如果想查看某个搜索结果的上下文，可以根据目标文件类型选择以下两个工具，并传入目标文件路径与目标行号。\n"
            f"1. 对于 `.py` 文件，使用 `get_code_context` 工具。\n"
            f"2. 对于其他文件，使用 `get_file_context` 工具。"
        )

        return "\n".join(output_lines)

    async def _check_file(self, rel_file_path: str) -> Tuple[int, str]:
        """
        检查文件，限制读取行数，以及读取文件信息
        """
        # 防止路径穿越
        try:
            abs_path = (self.repo_path / rel_file_path).resolve()
            if not str(abs_path).startswith(str(self.repo_path)):
                raise PermissionError(f"❌ 安全拦截: 拒绝访问仓库目录之外的文件 `{rel_file_path}`")
        except OSError as e:
            raise OSError(f"❌ 路径解析错误: `{str(e)}`")

        if not abs_path.exists():
            raise FileNotFoundError(f"❌ 错误: 文件不存在 `{rel_file_path}`")
        if not abs_path.is_file():
            raise IsADirectoryError(f"❌ 错误: `{rel_file_path}` 不是一个合法的文件（可能是目录）。")

        # 读取文件内容
        try:
            content = await asyncio.to_thread(Path(abs_path).read_text, encoding='utf-8', errors='replace')
            all_lines = content.splitlines()
        except Exception as e:
            raise RuntimeError(f"❌ 读取文件失败: `{str(e)}`")

        total_lines = len(all_lines)
        if total_lines == 0:
            raise ValueError(f"📄 `{rel_file_path}` 是一个空文件。")

        # 推断 Markdown 语法高亮标签
        label = abs_path.suffix.lower().lstrip('.')
        if not label:
            name = abs_path.name.lower()
            if name in ('dockerfile', 'makefile'):
                label = name
            elif name.startswith('.'): # 如 .env, .gitignore
                label = 'bash'
            else:
                label = 'text'
        
        return all_lines, total_lines, label

    async def read_file_content(
        self, 
        file_path: str, 
        start_line: int = 1,
        max_lines: int = 100,
    ) -> str:
        """
        精准读取指定文件内容的工具（用于读取 `.py` 以外的其他文件，如配置文件等）。
        
        【何时使用】：当需要深度审查基础设施构建文件（如 Dockerfile, docker-compose.yml）、环境配置与秘钥文件（如 .env, config.yaml）、或依赖项清单（如 pyproject.toml）等非代码文件时调用。
        
        Args:
            file_path (str): 目标文件的相对路径。
            start_line (int, optional): 起始读取行号，默认 1。
            max_lines (int, optional): 单次读取的最大行数，默认 100。该值只能小于或等于100。

        Returns:
            str: 附带行号的 Markdown 格式文件内容片段。
        """
        try:
            all_lines, total_lines, label = await self._check_file(file_path)
        except Exception as e:
            return str(e)

        if start_line > total_lines:
            return f"❌ 错误: 请求的起始行号 ({start_line}) 已超出文件总行数 ({total_lines})。"

        max_lines = max(0, min(max_lines, self.config_max_lines))

        # 计算切片边界
        idx_start = start_line - 1 # 转为 0-indexed
        idx_end = min(idx_start + max_lines, total_lines) # 都是开区间坐标
        chunk_lines = all_lines[idx_start:idx_end]
        is_ended = idx_end >= total_lines

        # 拼接排版
        output_lines = [
            f"### 📄 文件内容: `{file_path}`",
            f"> **总计行数**: {total_lines} 行 | **当前展示**: {start_line}-{idx_end} 行",
            f"```{label}"
        ]
        
        for i, line in enumerate(chunk_lines):
            if len(line) > self.single_line_max_length:
                hidden_chars = len(line) - self.single_line_max_length
                line = line[:self.single_line_max_length] + f" ... [单行超长截断，已隐藏 {hidden_chars} 字符]"

            current_line_num = start_line + i
            output_lines.append(f"{current_line_num:4d} | {line}") # 附带行号
            
        output_lines.append("```")

        # 底部操作指引
        if not is_ended:
            next_start = idx_end + 1
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **文件截断提示**: 当前仅展示至第 {idx_end} 行，文件尚未结束。\n"
                f"若需继续阅读后续配置内容，请再次调用此工具并传入参数 `start_line={next_start}`。\n"
                f"**注意**：某些配置文件可能拥有超大内容，很容易引起上下文爆炸，**如非必要，禁止反复读取无关配置文件**。\n"
                f"如果需要搜索某个内容，请使用 `global_search` 工具。"
            )
        else:
            output_lines.append(f"\n*(✅ 已达文件末尾)*")

        return "\n".join(output_lines)

    async def core_get_file_snippet(
        self, 
        file_path: str, 
        start_point: tuple, # 1-indexed
        end_point: tuple
    ) -> str:
        """
        根据行列坐标，精确读取任意文件中的目标文本内容。
        
        :param file_path: 目标文件相对路径
        :param start_point: 起始坐标 (start_line, start_column) (1-indexed)
        :param end_point: 结束坐标 (end_line, end_column) (1-indexed)
        :return: 供 LLM 直接阅读的 Markdown 格式化字符串
        """
        # 这里不捕获异常，直接向上抛出
        all_lines, total_lines, _ = await self._check_file(file_path)

        # 边界值安全校验
        start_line = max(1, min(start_point[0], total_lines))
        end_line = max(1, min(end_point[0], total_lines))
        
        if start_line > end_line:
            raise ValueError(f"❌ 错误: 起始行 ({start_line}) 不能大于结束行 ({end_line})。")

        # 坐标切片提取
        extracted_lines = []
        
        if start_line == end_line: # 单行内提取
            if start_point[1] > end_point[1]:
                raise ValueError(f"❌ 错误: 同一行内，起始列 ({start_point[1]}) 不能大于结束列 ({end_point[1]})。")

            line_str = all_lines[start_line - 1]
            start_column = max(0, min(start_point[1] - 1, len(line_str))) # 0-indexed
            end_column = max(0, min(end_point[1] - 1, len(line_str)))
            extracted_lines.append(line_str[start_column:end_column])
        else: # 跨行提取
            # 提取首行后半段
            first_line = all_lines[start_line - 1]
            start_column = max(0, min(start_point[1] - 1, len(first_line)))
            extracted_lines.append(first_line[start_column:])
            
            # 提取中间完整行
            for l in range(start_line, end_line - 1):
                extracted_lines.append(all_lines[l])
                
            # 提取末行前半段
            last_line = all_lines[end_line - 1]
            end_column = max(0, min(end_point[1] - 1, len(last_line)))
            extracted_lines.append(last_line[:end_column])

        return "\n".join(extracted_lines)

    async def core_get_file_context(
        self, 
        file_path: str, # 文件的相对路径
        start_line: int,
        end_line: int,
        context_lines: int = 20
    ) -> Tuple[str, Tuple]:
        """提取非代码文件的目标行号上下文"""
        # 这里不捕获异常，直接向上抛出
        all_lines, total_lines, label = await self._check_file(file_path)
        
        # 校验范围合法性
        if start_line > end_line:
            raise ValueError(f"❌ 错误: 起始行号 ({start_line}) 不能大于结束行号 ({end_line})。")
        
        # 统一转为 0-indexed，并防止越界
        start_line_0 = max(0, min(total_lines, start_line - 1))
        end_line_0 = max(0, min(total_lines, end_line - 1))

        # 将上下文行数扩展到 context_lines
        target_lines = end_line_0 - start_line_0 + 1
        remaining_lines = max(0, context_lines - target_lines)

        half_before = remaining_lines // 2
        idx_start = start_line_0 - half_before
        idx_end = end_line_0 + 1 + (remaining_lines - half_before)
        
        # 触碰上边界（文件头部）时，窗口整体下移
        if idx_start < 0:
            idx_end += (0 - idx_start)
            idx_start = 0
            
        # 触碰下边界（文件尾部）时，窗口整体上移
        if idx_end > total_lines: # idx_end 和 total_lines 都是开区间坐标
            idx_start -= (idx_end - total_lines)
            idx_end = total_lines
            # 确保 start 不为负数
            idx_start = max(0, idx_start)

        chunk_lines = all_lines[idx_start:idx_end]

        # 拼接排版
        output_lines = [
            f"### 🎯 上下文提取: `{file_path}`",
            f"> **目标行**: {start_line}-{end_line} 行",
            f"> **文件总行数**: {total_lines} 行 | **当前切片**: {idx_start + 1}-{idx_end} 行",
            f"```{label}"
        ]
        
        for i, line in enumerate(chunk_lines):
            current_line_num = idx_start + 1 + i

            if len(line) > self.single_line_max_length:
                hidden_chars = len(line) - self.single_line_max_length
                line = line[:self.single_line_max_length] + f" ... [单行超长截断，已隐藏 {hidden_chars} 字符]"
            
            # 给目标行打上 `=>` 箭头标记
            if start_line <= current_line_num <= end_line:
                prefix = "=>"
            else:
                prefix = "  "
                
            output_lines.append(f"{prefix} {current_line_num:4d} | {line}")
            
        output_lines.append("```")

        # ... 后续拼接逻辑保持不变 ...
        return "\n".join(output_lines), (idx_start + 1, idx_end)

    async def get_file_context(
        self, 
        file_path: str, 
        target_line: int, 
        context_lines: int = 20,
    ) -> str:
        """
        非 `.py` 文件的局部上下文提取工具。

        【何时使用】：当通过 global_search 或漏洞告警获知了可疑敏感词或配置项的具体行号，需要局部放大审查该行前后的信息时调用。
        
        Args:
            file_path (str): 目标文件的相对路径。
            target_line (int): 核心聚焦的中心行号（通常来源于搜索结果或告警信息）。工具会在返回文本中用 `=>` 明确高亮标出此行，方便快速定位。
            context_lines (int, optional): 上下文窗口的总展现行数（默认 20 行，目标行动态居中）。核心提示：仅当默认窗口未能覆盖完整的局部信息时，才适度调大此值。

        Returns:
            str: 附带行号及目标行指示符 (`=>`) 的 Markdown 代码块片段。
        """
        context_lines = max(0, min(context_lines, self.config_max_lines))

        try:
            context, _ = await self.core_get_file_context(
                file_path=file_path,
                start_line=target_line,
                end_line=target_line,
                context_lines=context_lines
            )

            # 底部操作指引
            output_lines = [context]
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **下一步建议**:\n"
                f"- 若上下文不足，可调大 `context_lines` 参数重新调用此工具（最大支持 {self.config_max_lines}）。\n"
                f"- 若需查阅此文件其他部分，可以：\n"
                f"  1. 使用 `read_file_content` 工具进行分页通读。\n"
                f"  2. 再次调用此工具，调整 `target_line` 参数，读取该文件的其他部分"
            )
            return "\n".join(output_lines)

        except Exception as e:
            # 统一将所有异常格式化为 LLM 友好的字符串
            return str(e)

    def as_tools(self) -> List:
        """将类方法包装为标准 LangChain 工具列表"""
        return [
            StructuredTool.from_function(coroutine=self.get_project_structure, name="get_project_structure"),
            StructuredTool.from_function(coroutine=self.global_search, name="global_search"),
            StructuredTool.from_function(coroutine=self.read_file_content, name="read_file_content"),
            StructuredTool.from_function(coroutine=self.get_file_context, name="get_file_context")
        ]