---
cwe_id: ["CWE-78"]
name: "Command_Injection"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
命令注入漏洞：操作系统命令注入漏洞发生于应用程序将未经过滤或转义的外部不可信输入，直接拼接并作为操作系统命令执行，导致攻击者能够利用Shell元字符（如 `;`, `|`, `&&`, `$()`）在宿主操作系统上以该进程的权限执行任意恶意命令。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
*   **Web框架请求参数**: `flask.request.args.get()`, `flask.request.form.get()`, `django.http.HttpRequest.GET.get()`, `fastapi.Query()`
*   **命令行参数**: `sys.argv[1:]`, `argparse` 解析的外部输入
*   **外部环境变量**: `os.environ.get()`, `os.getenv()`
*   **不可信文件/流读取**: 从用户上传的文件、数据库（二次注入）或未校验的第三方API读取的文本。

##### 2. 危险执行点 (Sinks)
*   `os.system(cmd)`
*   `os.popen(cmd)`
*   `subprocess.Popen(cmd, shell=True)`
*   `subprocess.call(cmd, shell=True)`
*   `subprocess.check_call(cmd, shell=True)`
*   `subprocess.check_output(cmd, shell=True)`
*   `subprocess.run(cmd, shell=True)`
*   `commands.getstatusoutput(cmd)` / `commands.getoutput(cmd)` (Python 2 遗留)

##### 3. 传播路径特征
*   **字符串拼接**: 使用 `+`, `f-string` (例如 `f"ping -c 4 {user_ip}"`), `%` 格式化 (例如 `"ls %s" % directory`), 或 `.format()` 将 Sources 组合成完整命令字符串。
*   **变量传递**: 被拼接的命令字符串被赋值给变量，最终直接作为参数传递给带有 `shell=True` 特性的 Sinks。
*   **缺乏过滤**: 在数据流向 Sinks 的过程中，未经过白名单校验或安全的转义函数（如 `shlex.quote()`）处理。

#### 3. 典型误报样例

误报通常发生在使用了安全的 API 调用方式，或者对输入进行了严格限制的情况下：

**误报样例 1：使用了 `shell=False`（默认值）与列表传参**
```python
# 安全：输入作为单独的参数传递，不会被Shell解析元字符
user_input = request.args.get("ip")
subprocess.run(["ping", "-c", "4", user_input])
```

**误报样例 2：经过了可靠的转义**
```python
import shlex
user_input = request.args.get("filename")
# 安全：shlex.quote 能够正确转义Shell元字符
safe_input = shlex.quote(user_input)
subprocess.run(f"ls -l {safe_input}", shell=True)
```

**误报样例 3：输入来源为内部硬编码或受信任配置**
```python
# 误报：虽然使用了 shell=True，但 cmd 来源并非不可信输入
INTERNAL_CMD = "df -h"
subprocess.run(INTERNAL_CMD, shell=True)
```

#### 4. 证实标准

当以下所有条件均满足时，Agent应将此告警判定为**真实漏洞（True Positive）**：
1. **输入可控:** 数据追踪源头确认为外部用户可控的数据（如 HTTP 请求参数）。
2. **触达危险Sink:** 数据流最终进入了已知会导致命令执行的 Sink 函数（如 `os.system` 或包含 `shell=True` 参数的 `subprocess` 家族函数）。
3. **解析为Shell命令:** 传入 Sink 的参数是字符串类型，且包含被直接拼接的外部输入变量。
4. **防御缺失:** 在 Source 到 Sink 的传播路径上，不存在有效的黑/白名单校验，也没有使用 `shlex.quote()` 等标准转义库对变量进行无害化处理。

#### 5. 证伪标准

当满足以下任意一个条件时，Agent应将此告警判定为**误报（False Positive）**：
1. **安全的子进程调用:** 目标调用是 `subprocess` 家族函数，并且未显式设置 `shell=True`（即默认为 `False`），且命令是以列表（List）形式传递的。
2. **存在有效转义:** 外部输入在拼接到命令字符串之前，明确通过了 `shlex.quote()` 函数的处理。
3. **存在强校验:** 输入在执行前经过了严格的类型转换（如强制转为 `int`）或严格的枚举/白名单校验（如 `if user_input in ["status", "restart"]:`）。
4. **数据流中断:** 变量在触达 Sink 之前被重新赋值为安全的静态值，或者启发式扫描器追踪的 Source 实际上是一个不可被外部篡改的内部变量/硬编码常量。