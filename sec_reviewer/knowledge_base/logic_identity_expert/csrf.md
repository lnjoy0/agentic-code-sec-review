---
cwe_id: ["CWE-352"]
name: "CSRF"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
CSRF（Cross-Site Request Forgery）：攻击者诱导已登录受害者在存在漏洞的Web应用中执行非本意的状态修改操作，其根本原因在于服务端在依赖浏览器自动发送的隐式身份凭证（如Cookie、Session）进行鉴权时，未校验请求来源的合法性（如缺失 CSRF Token 或 Referer 校验）。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
此漏洞通常发生在处理 HTTP 请求的视图函数（View/Handler）或路由映射（Router）处。
在 Python 框架中（如 Django views, Flask routes, FastAPI endpoints），应用主要通过解析浏览器自动携带的 Cookie（如 Django 的 `request.session`、Flask 的 `session` 对象、或直接读取 `request.cookies`）来获取当前用户的身份标识（User ID）。
**上下文风险点**：由于浏览器会在跨域请求时自动携带目标网站的 Cookie，如果业务入口仅依赖 Cookie 提取身份上下文，而未对请求的具体来源发起验证，就会产生上下文混淆，使攻击者能够伪造受害者身份发起请求。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
漏洞端点包含了导致服务器状态发生实质性变更（Side-effect）的敏感业务操作。
典型的敏感动作包括但不限于：
- 执行了基于 ORM 的数据写入/修改/删除操作（如 `User.objects.filter(id=request.user.id).update(email=new_email)`、`db.session.commit()`）。
- 触发了关键状态机跃迁（如订单状态变更为已支付、工单状态变更为已审批）。
- 调用了内部微服务或异步任务（如 Celery task）发起了资金流转、权限提权或密码重置动作。
注意：如果入口点存在滥用 `GET` 请求来执行上述状态修改的情况，将大幅降低攻击者的利用门槛。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
代码中缺失了阻止伪造请求的必要逻辑锁和鉴权门禁：
- **缺失防御性 Token**：未使用或禁用了框架内置的 CSRF 保护中间件（如 Django 中滥用 `@csrf_exempt` 装饰器，或 Flask 中未全局启用 `CSRFProtect`），且业务逻辑中未对提交的表单/请求头中的 Token 进行校验。
- **缺失同源性校验**：未对 `Origin` 或 `Referer` HTTP Header 进行白名单校验。
- **缺失自定义 Header 约束**：未要求请求必须携带前端特有的自定义 Header（如 `X-Requested-With: XMLHttpRequest` 或 `X-CSRFToken`），从而使得简单的 HTML 表单即可触发跨域 POST 请求。
- **Cookie 属性缺失**：身份认证 Cookie 未设置 `SameSite=Lax` 或 `SameSite=Strict` 属性，允许浏览器在所有跨站请求中携带凭证。

#### 3. 典型误报样例

1. **基于 Token 的无状态 API（最常见误报）**：扫描器标记了某个修改用户资料的接口，但该接口（如 FastAPI/Django REST framework 开发的接口）身份验证依赖于 HTTP Header 中的 `Authorization: Bearer <JWT>` 或 `X-Token`，完全不读取任何 Cookie。由于浏览器**不会**自动在跨站请求中添加此类 Header，CSRF 攻击无法成立。
2. **只读接口 (Read-Only Endpoint)**：扫描器标记了某个仅执行 ORM `.get()`、`.filter()` 并返回数据的 `GET` 或 `POST` 接口，该接口没有任何改变服务器状态的 Side-effect。此类情况顶多构成信息泄露（若存在 CORS 配置不当），但不构成 CSRF。
3. **框架全局保护已开启**：启发式扫描器因在当前视图函数中未看到 `csrf_protect` 的显式调用而报警，但实际上项目的 `settings.py` (Django) 或主应用文件 (Flask) 中已经全局挂载了 CSRF 防御中间件（如 `django.middleware.csrf.CsrfViewMiddleware`），且当前视图并未被豁免。
4. **严格的 Content-Type 限制**：接口强制校验了 `Content-Type: application/json`。虽然可以通过 Fetch/XHR 构造此请求，但由于触发了非简单请求的 CORS Preflight（`OPTIONS` 请求），若目标服务器无漏洞的 CORS 配置，浏览器将拦截跨站提交，从而阻止攻击。

#### 4. 证实标准

当满足以下**全部条件**时，可判定为真实漏洞：
1. **凭证自动携带**：确认代码中的身份鉴别依赖于 Cookie（Session-based auth）。
2. **产生状态变更**：确认被审计的函数内部包含实质性的数据库修改、状态变更或敏感 API 调用。
3. **防护机制缺失**：
   - 确认代码所在位置关闭了框架默认 CSRF 保护（例如：Django `views.py` 中的函数被 `@csrf_exempt` 装饰）。
   - **且** 没有要求额外的自定义鉴权 Header。
   - **且** 没有手动验证 `Referer`/`Origin`。
   - **且** 相关 Cookie 属性（若能在代码/配置中溯源）没有配置为 `SameSite=Strict`。

#### 5. 证伪标准

只要满足以下**任意一项**，即可判定为误报：
1. **非 Cookie 鉴权**：接口鉴权强依赖于每次请求主动附带的 Header 凭证（JWT, API Key），而不依赖系统 Cookie。
2. **纯读取无副作用**：接口操作仅查询数据，未修改任何数据库或系统状态（幂等性操作）。
3. **全局/隐式防护存在**：系统通过中间件/拦截器（Middleware/Interceptors）全局启用了 CSRF 校验，且当前路由未被豁免（例如 Django 中未发现 `@csrf_exempt`）。
4. **CORS 预检阻断**：接口严格要求 `application/json` 或其他自定义 Header，且没有存在漏洞的 `Access-Control-Allow-Origin: *` 和 `Access-Control-Allow-Credentials: true` 的组合配置，使得浏览器预检机制（Preflight）天然阻断了跨站请求。