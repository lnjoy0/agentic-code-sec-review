---
cwe_id: ["CWE-532"]
name: "Sensitive_Data_Logging"
domain: ["Data_Asset_Expert", "General_Expert"]
---

#### 1. 漏洞机制
程序在处理凭证、个人身份信息（PII）、财务数据或业务机密等敏感信息时，未进行掩码或脱敏处理，便直接通过日志库或输出函数将其写入持久化文件、控制台或外部监控系统中，从而导致高价值数据面临被未授权人员（如运维人员、攻击者）窃取或滥用的风险。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
*   **敏感变量特征**：变量名或字典键名包含 `password`, `passwd`, `secret`, `api_key`, `token`, `session_id`, `ssn`, `credit_card`, `authorization`, `private_key` 等。
*   **高危API/操作**：
    *   Python 标准日志库：`logging.debug()`, `logging.info()`, `logging.error()`, `logger.warning()`, `logger.exception()` 等。
    *   标准输出与错误：`print()`, `sys.stdout.write()`, `sys.stderr.write()`。
    *   第三方监控/APM与异常收集库：`sentry_sdk.capture_exception()`, `sentry_sdk.capture_message()`, `traceback.print_exc()`。
    *   Web 框架的上下文对象：Flask/Django/FastAPI 的 `request.body`, `request.headers`, `request.form`。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
*   **直接拼接或格式化敏感明文**：使用 f-string 或 `%s` 将包含密码或密钥的字符串直接写入日志。
    ```python
    # 错误写法：直接记录明文密码
    logger.info(f"User login attempt with password: {password}")
    ```
*   **全量输出包含敏感字段的复合对象**：将未过滤的字典、JSON 负载或 HTTP 请求/响应对象整体打印，导致内部深层嵌套的敏感字段外泄。
    ```python
    # 错误写法：直接记录包含 authorization 头的全量 HTTP 请求头或 body
    logger.debug("Received request headers: %s", request.headers)
    logger.info("User created: %s", user_dict_with_secrets)
    ```
*   **不当的异常堆栈记录**：在捕获异常时，部分配置或调试工具会将局部变量（locals）全量 dump 到日志中，若局部变量中正好存放了密钥，则会隐式外带。

##### 3. 缺失的安全控制 (Missing Security Controls)
*   **缺失字符串掩码（Masking/Redaction）**：在传入日志 API 之前，未对敏感字符串进行截断或替换（如将 `123456` 转换为 `***` 或 `12...56`）。
*   **缺失字段级过滤（Field-level Filtering）**：在记录字典或 JSON 前，未剔除或混淆 `password`、`token` 等高危 Key，未采取“白名单机制”仅记录安全字段。
*   **缺失全局日志过滤器（Logging Filters）**：未在 Python 的 `logging` 模块中注册自定义的 `logging.Filter` 来在全局层面利用正则拦截并替换敏感模式（如信用卡号正则、JWT token 特征）。

#### 3. 典型误报样例
*   **日志中记录的是变量名而非变量值**：代码仅记录了将要使用的配置项名称，并没有打印其实际的值。
    ```python
    # 误报样例：并未输出实际的 key 值
    logger.info("Successfully loaded API_KEY from environment.")
    ```
*   **已脱敏或哈希化的数据**：变量命名虽然包含敏感词，但其值在传递给日志库前已经过加密、哈希或掩码处理。
    ```python
    # 误报样例：记录的是哈希值或掩码后的值
    logger.debug(f"User password hash: {password_hash}")
    logger.info("Using token: %s", mask_token(api_token))
    ```
*   **记录的是元数据（长度/类型/布尔状态）**：并未暴露真实数据，只暴露了数据特征。
    ```python
    # 误报样例：仅记录长度
    logger.debug("Received token of length %d", len(api_key))
    ```
*   **测试代码与测试固件中的硬编码日志**：位于 tests/, conftest.py 或 test_*.py 文件中，记录的仅仅是无业务风险的 Mock/Dummy 数据。
    ```python
    # 误报样例：测试代码中的虚拟密钥
    logger.info("Test runner using fake secret: test_secret_123")
    ```

#### 4. 证实标准

当满足以下**所有条件**时，即可研判为真实漏洞（True Positive）：
1.  **数据源确认**：通过数据流分析（Data Flow Analysis），确认被记录的变量确实来源于敏感输入（如接收前端传来的密码、从环境变量/Vault读取的真实密钥、包含 PII 的数据库查询结果）。
2.  **触发点确认**：确认该变量被作为参数传递给了 `logging` 等持久化输出函数的输出负载中。
3.  **链路无净化**：在数据源赋值到日志触发点之间的数据流链路上，**不存在**针对该变量的字符串替换、切片脱敏、哈希计算或白名单字段过滤操作。
4.  **环境确认**：确认包含该代码的模块属于生产环境业务逻辑（非单纯的单元测试文件）。

#### 5. 证伪标准

当满足以下**任一条件**时，即可研判为误报（False Positive）：
1.  **链路已净化**：数据流途径了明确的清洗函数（如 `sanitize_dict()`, `mask_credit_card()`, `hashlib.sha256().hexdigest()`），日志实际打印的是安全数据。
2.  **安全上下文/占位符**：输出的字符串是一个固定常量、占位符或仅代表字段的存在性，如 `logger.info("Key format is invalid")` 或 `logger.info(f"API key is set: {bool(api_key)}")`。
3.  **全局拦截器存在**：当前 Python 项目初始化时，为 Logger 绑定了可靠的、基于正则或键名的全局敏感词过滤组件（如自定义的 `SanitizedFormatter`），因此即使业务层直接传入敏感对象，底层也不会泄露。
4.  **非敏感数据证明**：通过语义或上下文确认变量名虽具迷惑性（如 `secret_version`），但其实际内容为公开信息（如整数型的版本号、枚举值等）。