---
cwe_id: ["CWE-22"]
name: "Path_Traversal"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
攻击者通过控制输入参数，向应用程序传递包含目录跳转字符（如`../`）或绝对路径的路径字符串，绕过预期的目录访问限制，从而在Python的文件系统API中实现对服务器任意文件的非授权读取、写入、覆盖或删除。

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

#### 4. 证实标准

污点追踪连贯：存在从 Sources 到 Sinks 的完整数据流，且参数被直接用于文件路径的构建。
1. **缺乏有效净化/校验:** 传播路径中没有使用 `secure_filename()`、`os.path.basename()` 等函数提取文件名，也没有执行严格的绝对路径前缀校验（`startswith`）。
2. **命中Python特有逻辑漏洞:** 代码仅使用了 `os.path.join(BASE, user_input)`，且未拦截 `user_input` 传入绝对路径（如 `/etc/passwd`）导致 BASE 被截断覆盖的情况。
3. **黑名单替换绕过:** 代码使用了不安全的替换逻辑，例如仅执行一次 `user_input.replace("../", "")`，攻击者可通过双写（如 `..././` 或 `....//`）实现绕过。

#### 5. 证伪标准

1. **路径脱敏/净化:** 污点在到达执行点前，经过了 `os.path.basename()``、werkzeug.utils.secure_filename()` 或 `Path(user_input).name` 的处理，已被彻底剥离了目录层级。
2. **安全框架API层拦截:** 执行点使用了框架推荐的安全文件分发 API，如 Flask 的 `send_from_directory()`。
3. **白名单/映射校验:** 用户输入在进入路径拼接前，经过了强白名单校验（如 `if input not in whitelist: return`），或仅作为映射关系的 Key 获取后端硬编码的真实路径。
4. **严密的前缀边界校验:** 污点数据在最终文件操作前，已被转换为绝对路径，并严格校验了其 `startswith()` 预设的根目录绝对路径（且确保预设根目录末尾带有 `os.sep` 路径分隔符，防止同名前缀目录绕过，如 `/base_path` 被 `/base_path_fake_dir` 绕过）。
5. **类型不符/强转:** 静态扫描器标记的输入源，在数据流传播中被强制转换为了非字符串安全类型（如 `int(user_input)`、`uuid.UUID(user_input)`），使得路径注入无法实施。