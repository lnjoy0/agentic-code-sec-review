---
cwe_id: ["CWE-200", "CWE-209", "CWE-312"]
name: "Sensitive_Information_Exposure"
domain: ["Data_Asset_Expert", "General_Expert"]
---

#### 1. 漏洞机制
程序在处理凭证、个人身份信息（PII）、财务数据、业务机密或系统内部运行状态（如堆栈跟踪、数据库结构）等敏感信息时，未进行有效的字段过滤、掩码脱敏或访问控制，便直接将其跨越信任边界暴露给未授权的主体。
常见的外泄途径包括：全量返回的 API 响应、前端页面渲染、详细的错误提示（Error Messages）、不安全的 URL 参数传输等。这会导致高价值数据面临被攻击者窃取、滥用或用于进一步渗透利用的风险。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
*   **敏感变量特征**：变量名或字典键名包含 `password`, `hash`, `secret`, `api_key`, `token`, `session_id`, `ssn`, `credit_card`, `phone_number`, `traceback`, `db_url` 等。
*   **高危API/操作**：
    *   Web 框架的响应序列化：Flask/FastAPI/Django 的 `jsonify()`, `Response()`, ORM 对象的直接序列化（如 `.__dict__` 或 `to_json()`）。
    *   异常处理与错误返回：将 `Exception.args`, `traceback.format_exc()`, `sys.exc_info()` 的结果直接作为 HTTP 响应体返回。
    *   外部 HTTP 请求构造：通过 `requests.get()`, `urllib` 将包含敏感密钥的字典直接拼接到 URL 的 `params` 参数中。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
*   **API 接口全量返回底层实体对象**：将从数据库查询出的包含密码哈希或隐私数据的 User 对象未经筛选直接返回给前端。
    ```python
    # 错误写法：将包含密码哈希或隐私字段的字典全量返回给客户端
    @app.route('/api/user/<int:user_id>')
    def get_user(user_id):
        user = db.query(User).get(user_id)
        return jsonify(user.to_dict())
    ```
*   **向客户端暴露详细的报错堆栈**：在全局异常捕获中，将包含系统路径、SQL 语句或局部变量的堆栈信息直接输出在 HTTP 500 响应中。
    ```python
    # 错误写法：直接将异常堆栈抛给外部用户
    @app.errorhandler(Exception)
    def handle_exception(e):
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500
    ```
*   **敏感参数置于 URL 中**：在进行 GET 请求或页面重定向时，将 Token 或密码置于 URL 参数中，导致敏感数据泄露在浏览器历史记录、代理日志或 Referer 头中。
    ```python
    # 错误写法：将敏感 token 放在 GET 参数中进行重定向或请求
    return redirect(f"https://example.com/dashboard?token={secret_token}")
    ```

##### 3. 缺失的安全控制 (Missing Security Controls)
*   **缺失响应视图裁剪（Response / DTO Filtering）**：在业务逻辑层与表现层之间，未使用数据传输对象（DTO）、GraphQL 字段限制或白名单机制来剔除高危 Key。
*   **缺失生产环境统一错误掩饰（Generic Error Handling）**：未针对生产环境配置全局兜底错误处理器，未将敏感的内部错误转化为通用且安全的提示（如“服务器内部错误，请稍后再试”）。
*   **缺失数据脱敏（Masking/Redaction）**：在前端展示或数据传输前，未对敏感字符串进行截断或掩码操作（如身份证号、银行卡号未做打码处理）。

#### 3. 典型误报样例
*   **暴露的是不透明标识符或公共属性**：返回的 JSON 中虽然包含看似敏感的 user_id 或 uuid，但其本身就是用于公开引用的公共标识符，不具备利用价值。
    ```python
    # 误报样例：公开展示的非敏感标识符
    return jsonify({"username": user.nickname, "profile_id": user.public_uuid})
    ```
*   **已正确脱敏的展示数据**：变量命名包含敏感词，但在序列化并响应给客户端之前已经经过了掩码处理。
    ```python
    # 误报样例：记录的是掩码后的值
    return jsonify({"bank_account": mask_card_number(user.bank_account)})
    ```
*   **授权边界内的合法访问**：接口返回了敏感信息，但该接口属于严密管控的管理后台（Admin Panel），且请求者拥有合法的管理员权限，数据流向了被授权的信任主体。

#### 4. 证实标准

当满足以下**所有条件**时，即可研判为真实漏洞（True Positive）：
1. **数据源确认**：确认被处理的变量包含真正的敏感信息（如 PII 数据、明文凭证、内部系统架构堆栈）。
2. **越权暴露确认**：确认该敏感数据跨越了信任边界，流向了未授权的接收方（如直接响应给普通用户的客户端、暴露在无需认证的公开接口、拼接到外部不可控的 URL 中）。
3. **链路无净化**：在数据被提取到最终输出的整个数据流链路上，不存在针对该变量的白名单字段过滤、DTO 映射拦截、字符串脱敏或掩码操作。
4. **环境确认**：属于生产环境或准生产环境代码，而非单纯生成 Dummy 数据的单元测试环境。

#### 5. 证伪标准

当满足以下**任一条件**时，即可研判为误报（False Positive）：
1. **链路已净化/裁剪**：数据流途径了明确的清洗对象或函数（如使用了 `pydantic` 的 `response_model` 限制了返回字段，或调用了 `sanitize_user_profile()`），最终暴露的是安全字段。
2. **安全上下文/兜底策略**：代码中捕获了异常，但输出给外部的仅为硬编码的安全常量或占位符，例如 `{"error": "Internal Server Error"}`。
3. **非敏感数据证明**：通过语义或上下文确认，被暴露的数据属于公开业务信息（如商品库存、公开文章内容、公共数字证书）。
4. **接收方具备合法权限**：该数据的流出目标本身就是被授权处理此类敏感数据的组件或高权限用户，符合业务的正常授权设计（如用户访问自己的个人中心获取自己的明文手机号）。