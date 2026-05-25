import logging
import collections
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from langchain_core.tools import StructuredTool
from langchain_core.runnables import RunnableConfig

logger = logging.getLogger(__name__)

class ProjectAnalyzer:
    """提供项目与文件分析工具"""
    
    def __init__(self, repo_path: str):
        self.repo_path  = repo_path

    def get_project_structure(
        self, 
        max_depth: int = 3, 
        ignore_dirs: Optional[List[str]] = None
    ) -> str:
        """
        获取代码仓库的宏观目录树结构（ASCII视图）。
        
        【何时使用】：当需要建立项目全局上下文、定位配置文件、寻找流量路由入口，或需确认特定文件是否属于测试/Mock目录时调用。
        
        Args:
            max_depth (int, optional): 遍历最大深度。默认3。警告：非必要勿轻易增大此值，以防返回过长导致上下文溢出。
            ignore_dirs (List[str], optional): 需额外跳过的目录名列表（默认已忽略 .git, venv, __pycache__ 等构建目录）。

        Returns:
            str: 项目目录结构的树状字符串。
        """
        path = Path(self.repo_path)
        if not path.exists():
            return f"Error: 路径 {self.repo_path} 不存在。"
        if not path.is_dir():
            return f"Error: 路径 {self.repo_path} 不是一个目录。"

        # 默认忽略的目录，主要为了节省 Token 和过滤无关安全审计的构建产物
        ignore_set = {
            '.git', '__pycache__', 'venv', '.venv', 'env', 
            '.idea', '.vscode', 'node_modules', 'dist', 'build'
        }
        if ignore_dirs:
            ignore_set.update(ignore_dirs)

        def generate_tree(dir_path: Path, prefix: str = '', current_depth: int = 1) -> str:
            if current_depth > max_depth:
                return prefix + "└── ... (达到最大深度)\n"

            try:
                # 获取目录内容并按文件夹在前、文件在后排序
                contents = list(dir_path.iterdir())
                contents = [c for c in contents if c.name not in ignore_set]
                contents.sort(key=lambda x: (x.is_file(), x.name.lower()))
            except PermissionError:
                return prefix + "└── ... (无权限访问)\n"

            tree_str = ""
            pointers = ['├── '] * (len(contents) - 1) + ['└── '] if contents else []

            for pointer, content in zip(pointers, contents):
                is_dir = content.is_dir()
                suffix = '/' if is_dir else ''
                tree_str += prefix + pointer + content.name + suffix + '\n'
                
                if is_dir:
                    extension = '│   ' if pointer == '├── ' else '    '
                    tree_str += generate_tree(content, prefix + extension, current_depth + 1)
                    
            return tree_str

        # 拼接排版
        output_lines = [
            f"### 📦 代码仓库目录树:",
            f"{path.name}/",
            generate_tree(path)
        ]
        return '\n'.join(output_lines)

    def global_search(
        self, 
        pattern: str, 
        file_pattern: Optional[str] = None, 
        is_regex: bool = True,
        max_results: int = 40
    ) -> str:
        """
        跨全量代码库的文本与正则表达式高速检索工具。

        【何时使用】：当需要全局查找危险函数（如 eval, os.system）、定位硬编码秘钥/弱加密算法、追踪特定路由入口与鉴权装饰器、或检索特定配置项时调用。
        
        Args:
            pattern (str): 目标检索字符串或正则表达式。
            file_pattern (str, optional): Glob风格的文件路径过滤器（如 '*.py', '*config*', 'src/**/*.py'）。强烈建议在已知上下文时传入，以大幅减少无关噪音。
            is_regex (bool, optional): pattern 是否作为正则表达式解析。默认 True。提示：若检索包含代码符号的纯文本（如 `password = "123"`），建议设为 False 以避免正则语法错误。
            max_results (int, optional): 限制返回的最大匹配行数。默认 40。警告：为防止上下文溢出，非必要请勿调大此值。

        Returns:
            str: 包含匹配文件路径、行号及对应代码片段的 Markdown 文本。
        """
        if not self.repo_path.exists():
            return f"❌ 错误: 仓库路径不存在 `{self.repo_path}`"

        # -n: 显示行号
        # --no-heading: 确保每行格式为 filepath:line:content
        cmd = ["rg", "-n", "--color=never", "--no-heading"]
        
        if not is_regex:
            cmd.append("-F") # 固定字符串匹配
            
        if file_pattern:
            cmd.extend(["-g", file_pattern])
            
        cmd.extend(["-e", pattern, str(self.repo_path)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_output = result.stdout
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                filter_msg = f" (在 `{file_pattern}` 中)" if file_pattern else ""
                return f"📄 未找到匹配 `{pattern}` 的搜索结果{filter_msg}。"
            else:
                logger.error(f"ripgrep 执行出错: {e.stderr}")
                return f"❌ 搜索失败: `{e.stderr.strip()}`"

        # 按文件分组
        matches_by_file = collections.defaultdict(list)
        total_matches = 0

        for line in raw_output.splitlines():
            if not line.strip():
                continue
                
            # 解析格式: filepath:line_number:content
            parts = line.split(":", 2)
            if len(parts) >= 3:
                file_path, line_num, content = parts[0], parts[1], parts[2]
                
                # 尝试转为相对路径，使输出更简短
                try:
                    from pathlib import Path
                    rel_path = str(Path(file_path).relative_to(self.repo_path))
                except ValueError:
                    rel_path = file_path
                    
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

        for file_path, lines in matches_by_file.items():
            if displayed_matches >= max_results:
                is_truncated = True
                break
                
            output_lines.append(f"\n#### 📄 `{file_path}`")
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

    def _check_file(self, file_path: str) -> Tuple[int, str]:
        """
        检查文件，限制读取行数，以及读取文件信息
        """
        # 防止路径穿越
        try:
            abs_path = (self.repo_path / file_path).resolve()
            if not str(abs_path).startswith(str(self.repo_path)):
                raise PermissionError(f"❌ 安全拦截: 拒绝访问仓库目录之外的文件 `{file_path}`")
        except OSError as e:
            raise OSError(f"❌ 路径解析错误: `{str(e)}`")

        if not abs_path.exists():
            raise FileNotFoundError(f"❌ 错误: 文件不存在 `{file_path}`")
        if not abs_path.is_file():
            raise IsADirectoryError(f"❌ 错误: `{file_path}` 不是一个合法的文件（可能是目录）。")

        # 读取文件内容
        try:
            with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
                all_lines = f.read().splitlines()
        except Exception as e:
            raise RuntimeError(f"❌ 读取文件失败: `{str(e)}`")

        total_lines = len(all_lines)
        if total_lines == 0:
            raise ValueError(f"📄 `{file_path}` 是一个空文件。")

        # 推断 Markdown 语法高亮标签
        ext = abs_path.suffix.lower().lstrip('.')
        if not ext:
            name = abs_path.name.lower()
            if name in ('dockerfile', 'makefile'):
                ext = name
            elif name.startswith('.'): # 如 .env, .gitignore
                ext = 'bash'
            else:
                ext = 'text'
        
        return all_lines, total_lines, ext

    def read_file_content(
        self, 
        file_path: str, 
        start_line: int = 1,
        max_lines: int = 200,
        config: RunnableConfig = None
    ) -> str:
        """
        精准读取指定非代码文件内容的工具（支持分页读取）。
        
        【何时使用】：当需要深度审查基础设施构建文件（如 Dockerfile, docker-compose.yml）、环境配置与秘钥文件（如 .env, config.yaml）、或依赖项清单（如 pyproject.toml）等非代码文件时调用。
        
        Args:
            file_path (str): 目标文件的相对路径。
            start_line (int, optional): 起始读取行号，默认 1。
            max_lines (int, optional): 单次读取的最大行数，默认 200。该值只能小于或等于200。

        Returns:
            str: 附带行号的 Markdown 格式文件内容片段。
        """
        try:
            all_lines, total_lines, ext = self._check_file(file_path)
        except Exception as e:
            return str(e)

        if start_line > total_lines:
            return f"❌ 错误: 请求的起始行号 ({start_line}) 已超出文件总行数 ({total_lines})。"

        config_max_lines = config['configurable'].get('context_config').context_max_lines
        max_lines = max(0, min(max_lines, config_max_lines))

        # 计算切片边界
        idx_start = start_line - 1 # 转为 0-indexed
        idx_end = min(idx_start + max_lines, total_lines) # 都是开区间坐标
        chunk_lines = all_lines[idx_start:idx_end]
        is_ended = idx_end >= total_lines

        # 拼接排版
        output_lines = [
            f"### 📄 文件内容: `{file_path}`",
            f"> **总计行数**: {total_lines} 行 | **当前展示**: {start_line}-{idx_end} 行",
            f"```{ext}"
        ]
        
        for i, line in enumerate(chunk_lines):
            current_line_num = start_line + i
            output_lines.append(f"{current_line_num:4d} | {line}") # 附带行号
            
        output_lines.append("```")

        # 底部操作指引
        if not is_ended:
            next_start = idx_end + 1
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **文件截断提示**: 当前仅展示至第 {idx_end} 行，文件尚未结束。\n"
                f"若需继续阅读后续配置内容，请再次调用此工具并传入参数 `start_line={next_start}`。"
            )
        else:
            output_lines.append(f"\n*(✅ 已达文件末尾)*")

        return "\n".join(output_lines)

    def core_get_file_snippet(
        self, 
        file_path: str, 
        start_point: tuple,
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
        all_lines, total_lines, _ = self._check_file(file_path)

        # 边界值安全校验
        start_line = max(1, min(start_point[0], total_lines))
        end_line = max(1, min(end_point[0], total_lines))
        
        if start_line > end_line:
            raise ValueError(f"❌ 错误: 起始行 ({start_line}) 不能大于结束行 ({end_line})。")

        # 坐标切片提取
        extracted_lines = []
        
        if start_line == end_line: # 单行内提取
            line_str = all_lines[start_line - 1]
            start_column = max(0, min(start_point[1] - 1, len(line_str)))
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

    def core_get_file_context(
        self, 
        file_path: str, 
        target_line: int, 
        context_lines: int = 20
    ) -> str:
        # 这里不捕获异常，直接向上抛出
        all_lines, total_lines, ext = self._check_file(file_path)
        
        if target_line < 1 or target_line > total_lines:
            raise ValueError(f"❌ 错误: 目标行号 ({target_line}) 超出文件有效范围 (1 - {total_lines})。")

        # 计算滑动窗口的起止索引
        idx_target = target_line - 1

        # 计算理想状态下的起止索引，确保总长度严格等于 context_lines
        half_before = context_lines // 2
        idx_start = idx_target - half_before
        idx_end = idx_start + context_lines
        
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
            f"### 🎯 上下文提取: `{file_path}` (Line {target_line})",
            f"> **文件总行数**: {total_lines} 行 | **当前切片**: {idx_start + 1}-{idx_end} 行",
            f"```{ext}"
        ]
        
        for i, line in enumerate(chunk_lines):
            current_line_num = idx_start + 1 + i
            
            # 给目标行打上 `=>` 箭头标记
            if current_line_num == target_line:
                prefix = "=>"
            else:
                prefix = "  "
                
            output_lines.append(f"{prefix} {current_line_num:4d} | {line}")
            
        output_lines.append("```")

        # ... 后续拼接逻辑保持不变 ...
        return "\n".join(output_lines)

    def get_file_context(
        self, 
        file_path: str, 
        target_line: int, 
        context_lines: int = 20,
        config: RunnableConfig = None
    ) -> str:
        """
        非代码文件局部上下文提取工具。

        【何时使用】：当通过 global_search 或漏洞告警获知了可疑敏感词或配置项的具体行号，需要局部放大审查该行前后的信息时调用。
        
        Args:
            file_path (str): 目标文件的相对路径。
            target_line (int): 核心聚焦的中心行号（通常来源于搜索结果或告警信息）。工具会在返回文本中用 `=>` 明确高亮标出此行，方便快速定位。
            context_lines (int, optional): 上下文窗口的总展现行数（默认 20 行，目标行动态居中）。核心提示：仅当默认窗口未能覆盖完整的局部信息时，才适度调大此值。

        Returns:
            str: 附带行号及目标行指示符 (`=>`) 的 Markdown 代码块片段。
        """
        config_max_lines = config['configurable'].get('context_config').context_max_lines
        context_lines = max(0, min(context_lines, config_max_lines))

        try:
            context = self.core_get_file_context(file_path, target_line, context_lines)

            # 底部操作指引
            output_lines = [context]
            output_lines.append("\n---")
            output_lines.append(
                f"💡 **下一步建议**:\n"
                f"- 若上下文不足，可调大 `context_lines` 参数重新调用此工具（最大支持 {self.max_lines}）。\n"
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
            StructuredTool.from_function(func=self.get_project_structure, name="get_project_structure"),
            StructuredTool.from_function(func=self.global_search, name="global_search"),
            StructuredTool.from_function(func=self.read_file_content, name="read_file_content"),
            StructuredTool.from_function(func=self.get_file_context, name="get_file_context")
        ]