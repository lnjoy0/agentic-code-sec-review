---
cwe_id: ["CWE-22"]
name: "Path_Traversal"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
路径穿越漏洞：攻击者通过控制输入参数，向应用程序传递包含目录跳转字符（如`../`）或绝对路径的路径字符串，绕过预期的目录访问限制，从而在Python的文件系统API中实现对服务器任意文件的非授权读取、写入、覆盖或删除。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
*   **Web框架请求参数:**
    *   Flask: `request.args.get('filename')`, `request.form['file']`, `request.view_args`
    *   Django: `request.GET.get('path')`, `request.POST['path']`, `kwargs.get('filepath')`
    *   FastAPI/Starlette: `filepath: str` (Query, Path, Form参数)
*   **外部文件/环境:** `sys.argv[1]`, `os.environ.get()`, 从不受信任的数据库或外部API获取的路径字段。
*   **压缩包解析 (Zip Slip变体):** `tarfile.extractall()`, `zipfile.ZipFile.extract()` （恶意压缩包内含`../`路径的文件项）。

##### 2. 危险执行点 (Sinks)
*   **文件读取/写入:** `open(path, 'r')`, `Path(path).read_text()`, `Path(path).write_bytes()`
*   **文件系统操作:** `os.remove(path)`, `os.unlink(path)`, `shutil.rmtree(path)`, `os.rename(src, dst)`
*   **框架文件响应:**
    *   Flask: `send_file(path)`
    *   FastAPI/Starlette: `FileResponse(path)`
    *   Django: `HttpResponse(open(path, 'rb'))`, `FileResponse(open(path, 'rb'))`
*   **模块动态加载/执行:** `exec(open(path).read())`, `importlib.import_module(path)`

##### 3. 传播路径特征
*   **直接字符串拼接:** `file_path = BASE_DIR + "/" + user_input` 或 `f"{BASE_DIR}/{user_input}"`
*   **危险的路径组合 (`os.path.join` 滥用):** `os.path.join(BASE_DIR, user_input)`。注意Python特有安全陷阱：如果 `user_input` 以 `/` 开头（即绝对路径），`BASE_DIR` 将被忽略，函数直接返回 `user_input`。
*   **未经验证的路径解析:** 使用 `os.path.abspath(path)` 或 `Path(path).resolve()` 解析了带 `../` 的污点路径，但未在后续逻辑中校验解析结果是否仍在安全根目录内。

#### 3. 典型误报样例

**误报样例 1：使用了安全的框架内置函数**
```python
from flask import send_from_directory
@app.route('/download/<path:filename>')
def download_file(filename):
    # send_from_directory 内部实现了严密的路径穿越防护，属于误报
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
```
**误报样例 2：经过了有效的文件名净化 (Sanitization)**
```python
import os
from werkzeug.utils import secure_filename
def save_file(user_input):
    # secure_filename 会移除路径分隔符，如 '../../../etc/passwd' 会被过滤
    safe_name = secure_filename(user_input)
    # os.path.basename 也会提取纯文件名，舍弃路径部分，同样安全
    # safe_name = os.path.basename(user_input)
    path = os.path.join(UPLOAD_DIR, safe_name)
    open(path, 'w').write("data")
```
**误报样例 3：基于前缀的绝对路径校验 (Validation)**
```python
import os
def read_safe(user_input):
    target_path = os.path.abspath(os.path.join(BASE_DIR, user_input))
    base_path = os.path.abspath(BASE_DIR) + os.sep
    # 验证解析后的最终绝对路径是否以安全的base_path开头
    if target_path.startswith(base_path):
        return open(target_path).read()
    return "Access Denied"
```
**误报样例 4：白名单/映射字典模式 (Allowlist)**
```python
ALLOWED_FILES = {"doc1": "document_v1.pdf", "doc2": "document_v2.pdf"}
def get_file(user_input):
    # user_input 仅作为字典的 key，不直接参与路径构造
    if user_input in ALLOWED_FILES:
        return open(os.path.join(BASE_DIR, ALLOWED_FILES[user_input])).read()
```

#### 4. 绕过技巧
1. 对于过滤方法： `name.replace('../', '')`，该方法会将 `name` 中的所有 `../` 都替换为空字符串
   1. 如果该方法仅执行一次的话，可以使用 `....//` 来绕过（`....//` 被替换一次 `../` 之后仍然是 `../`）

#### 4. 证实标准
智能体在研判扫描报告时，若要确认该漏洞为**真实漏洞 (True Positive)**，需同时满足以下条件：
1.  **完整污点链路**: 存在从外部不可信输入（Source）到文件操作 API（Sink）的明确数据流。
2.  **过滤缺失**: 在数据传播路径中，未对污点数据进行针对目录跳转字符（`../`, `..\`）或绝对路径符号（`/`, `C:\`）的有效清洗或拦截。
3.  **不安全的路径组装**: 采用了直接字符串拼接，或使用了 `os.path.join` 但未对输入的绝对路径特性进行防御。
4.  **越权可能性**: 未在最终执行前将路径转化为绝对路径并判断其是否隶属于预期的基础安全目录内。

#### 5. 证伪标准
智能体在研判扫描报告时，只要代码逻辑满足以下**任意一条**，即可判定为**误报 (False Positive)** 并将其滤除：
1.  **源头阻断**: 污点数据在进入 Sink 前被 `os.path.basename()` 或 `werkzeug.utils.secure_filename()` 处理，已失去包含目录结构的可能。
2.  **白名单重写**: 用户输入并未直接作为路径参数，而是作为标识符（ID、Key）匹配硬编码在后端的字典或数据库中的绝对路径。
3.  **严格边界约束**: 执行了规范化和边界检查组合技，如先使用 `os.path.abspath()`（或 `pathlib.Path.resolve()`）解析出绝对路径，随后使用 `startswith(base_dir)`（或 `is_relative_to()`）验证路径未越界。
4.  **安全组件兜底**: 终端 Sink 是已知内部已封装路径穿越防御机制的函数（如 Flask 的 `send_from_directory`），且基础目录参数（第一个参数）是固定安全的。