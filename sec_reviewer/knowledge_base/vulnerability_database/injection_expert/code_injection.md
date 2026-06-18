---
cwe_id: ["CWE-94"]
name: "Code_Injection"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
代码注入漏洞发生在应用程序将未经严格校验或过滤的外部用户可控输入，直接拼接到动态代码执行函数（如 `eval()`、`exec()`）中并执行，从而允许攻击者逃逸原有代码逻辑，在当前应用上下文中执行任意恶意Python代码。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
*   **Web框架请求对象:** `request.args.get()`, `request.form[]`, `request.json`, `request.headers` (如 Flask, Django, FastAPI 等框架)。
*   **文件与系统交互:** 读取用户上传的恶意文件内容、解析被污染的配置文件（如 `.py` 配置文件动态加载）。
*   **反序列化/解码:** `pickle.loads()`, `yaml.load()` (使用不安全的 Loader)，或从数据库/缓存中读取的未校验数据。
*   **命令行参数:** `sys.argv` (在将其传递给动态执行函数的场景下)。

##### 2. 危险执行点 (Sinks)
*   **原生内置函数:** 
    *   `eval(expression, globals=None, locals=None)`
    *   `exec(object, globals=None, locals=None)`
    *   `compile(source, filename, mode)`
*   **隐式/间接执行点:**
    *   `__import__(user_input)` 或 `importlib.import_module(user_input)` (当用于加载恶意本地模块时)。
    *   `type(name, bases, dict)` (动态创建类时，恶意控制方法或属性)。
    *   `timeit.timeit(stmt=user_input)` (其底层会使用 `exec` 执行语句)。

##### 3. 传播路径特征
*   **直接拼接:** 使用 `+` 操作符、`%` 格式化、`.format()` 方法或 `f-string` 将 Source 直接嵌入到 Sink 所需的字符串中。
    *   *示例:* `eval("math." + user_input)`
*   **无害化处理缺失:** 数据流在到达 Sink 之前，未经过正则表达式强校验、白名单过滤或类型强制转换（如未转换为 `int`）。
*   **不可信的作用域传递:** 将包含恶意输入的字典直接作为 `globals` 或 `locals` 参数传递给 `eval()` 或 `exec()`。

#### 3. 典型误报样例
*   **场景一：使用了安全的替代方案 `ast.literal_eval`**
    *   *代码:* `data = ast.literal_eval(request.form['data'])`
    *   *说明:* `ast.literal_eval` 只能计算 Python 基础数据类型（字符串、数字、元组、列表、字典、布尔值和 None），无法执行函数调用或复杂表达式，通常不构成代码注入。
*   **场景二：被判定为 Source 的变量实际上是内部硬编码 (Hardcoded)**
    *   *代码:* `config_key = "DEFAULT_TIMEOUT"; eval(f"app.config.{config_key}")`
    *   *说明:* 虽然使用了危险函数，但输入源并非外部用户可控，而是内部固定变量。
*   **场景三：严格的白名单/字典映射过滤**
    *   *代码:* `if func_name in ['sin', 'cos', 'tan']: eval(f"math.{func_name}(x)")`
    *   *说明:* 输入被严格限制在已知安全的白名单内，攻击者无法注入任意代码。
*   **场景四：混淆漏洞类型（与命令注入 CWE-78 混淆）**
    *   *代码:* `os.system(request.args.get('cmd'))`
    *   *说明:* 这是操作系统命令注入（Command Injection），而非 Python 语言层面的代码注入（Code Injection）。尽管都很危险，但在多智能体研判时应划分为不同的漏洞类型。

#### 4. 证实标准
当以下所有条件均满足时，Agent应将此告警判定为**真实漏洞（True Positive）**：
1.  **数据可控性:** 明确追踪到输入数据源（Source）来自外部不可信用户输入（如 HTTP 请求、第三方 API、不可信数据库）。
2.  **触达危险点:** 数据流明确到达了 Python 的代码执行函数（Sink，主要为 `eval` 或 `exec`）。
3.  **缺乏有效防御:** 在 Source 到 Sink 的完整传播路径（Data Flow）中，**不存在**以下任何一种阻断措施：
    *   类型强制转换（例如 `int(user_input)`）。
    *   严格的正则过滤（例如仅允许纯数字或字母 `^[a-zA-Z0-9_]+$`）。
    *   闭环的白名单校验。
4.  **上下文可逃逸:** 注入点周围的字符串拼接方式允许攻击者通过特定的 payload（如闭合引号 `"`、闭合括号 `)`、引入换行符 `\n` 或 `#` 注释符）逃逸出开发者预期的语义结构，执行额外的恶意语句。

#### 5. 证伪标准
当满足以下任意一个条件时，Agent应将此告警判定为**误报（False Positive）**：
1.  **死胡同传播 (Dead End):** 扫描器报告的输入源（Source）实际上无法被外部用户控制（如本地环境变量、配置文件、硬编码常量）。
2.  **安全函数替代:** 目标代码实际使用的是 `ast.literal_eval()`，而非 `eval()`。
3.  **强类型截断:** 外部输入在到达 Sink 前被强制转换成了基础安全类型（如 `int()` 或 `float()`），即使发生异常也只会抛出 ValueError，不会导致代码执行。
4.  **严格白名单限制:** 在执行流到达 Sink 之前，有明确的 `if input in ALLOW_LIST:` 或字典键值匹配逻辑，确保输入被完全锁定在安全范围内。
5.  **沙箱/受限环境（需谨慎评估）:** 虽使用了 `eval`，但通过严格限制 `globals` 和 `locals` 命名空间去除了所有内置函数（如 `eval(user_input, {"__builtins__": None}, {})`）。*注意：即使是 `__builtins__: None` 也可以通过特定魔术方法（如 `().__class__.__bases__[0].__subclasses__()`）逃逸，因此仅作为降级依据，不能作为绝对证伪标准，除非结合其他校验。*