---
cwe_id: ["CWE-79"]
name: "Cross-Site_Scripting"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
Web应用在将不受信任的外部输入动态拼接到HTML页面或HTTP响应返回给客户端前，未进行严格的上下文安全转义或过滤，导致攻击者的恶意脚本在受害者浏览器中作为有效代码被解析和执行。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
在Python Web框架中，通常是直接获取的HTTP请求数据：
- **Flask/Django等框架请求对象:**
  - `request.args.get('param')` / `request.GET.get('param')`
  - `request.form.get('param')` / `request.POST.get('param')`
  - `request.headers.get('User-Agent')`
  - `request.path` / `request.url`
- **FastAPI/Starlette:**
  - 路径参数或查询参数提取的字符串变量
  - `request.query_params['param']`
- **外部不可信数据源:**
  - 从未经验证的数据库字段读取的内容（可能导致存储型XSS）
  - 第三方API返回的数据

##### 2. 危险执行点 (Sinks)
导致XSS的执行点通常是关闭了自动转义的模板渲染，或直接返回未转义字符串的HTTP响应：
- **直接返回原始HTML (Flask/FastAPI/Django):**
  - Flask: `return f"<h1>Hello {user_input}</h1>"`
  - Django: `return HttpResponse(f"<h1>Hello {user_input}</h1>")`
  - FastAPI: `return HTMLResponse(content=f"<h1>Hello {user_input}</h1>")`
- **关闭自动转义的模板渲染 (Jinja2/Django Templates):**
  - Jinja2 过滤器: `{{ user_input | safe }}`
  - Django 过滤器: `{{ user_input | safe }}` 或 `{% autoescape off %}{{ user_input }}{% endautoescape %}`
  - 后端标记为安全字符串: 传递了 `Markup(user_input)` (Jinja2/MarkupSafe) 或 `mark_safe(user_input)` (Django)。
  - Jinja2 环境配置: `Environment(autoescape=False)`

##### 3. 传播路径特征
*   **字符串拼接**: 使用 `+`, `%s`, `str.format()`, 或 `f-string` 将 Source 直接拼接进包含HTML标签的字符串中，随后流入 Sink。
*   **缺乏净化**: 传播路径上未经过 `html.escape()`, `bleach.clean()`, `urllib.parse.quote()` 等标准净化函数处理。
*   **直接传递给上下文**: 数据作为字典或关键字参数传递给渲染函数，并在模板层被显式标记为安全（如传给前端被 `v-html` 或 `innerHTML` 接收，这也是DOM XSS的源头）。

#### 3. 典型误报样例

启发式扫描器常因上下文理解不足产生以下误报：
- **API接口误报（Content-Type安全）:** 代码虽然直接返回了拼接的污点字符串，但外层是一个JSON响应（如FastAPI默认返回 `JSONResponse`，或Flask返回 `jsonify(data)`），此时 `Content-Type: application/json` 会阻止浏览器解析执行HTML/JS。
- **强制类型转换拦截:** 污点数据在进入模板前被强制转换为了非字符串安全类型，例如 `user_id = int(request.args.get('id'))`。
- **ORM/数据库主键查询:** 污点数据仅用于数据库主键查询（如 `User.objects.get(id=user_id)`），并未直接反射到前端，扫描器可能误判为反射型XSS。
- **已使用可靠库清洗:** 污点数据进入 Sink 前经过了 `bleach.clean(user_input, tags=['b', 'i'])` 等专业清洗。

#### 4. 证实标准

当满足以下全部条件时，应研判为**真实漏洞（True Positive）**：
1. **完整污点路径:** 能够追踪到从外部输入（Source）到HTML渲染点（Sink）的数据流，且中途数据结构未被破坏。
2. **响应解析环境危险:** 漏洞触发点的HTTP响应 `Content-Type` 被明确设置为 `text/html`，或框架默认行为为返回HTML。
3. **转义机制缺失:** 
   - 目标变量在模板中使用了 `| safe` / `mark_safe`。
   - 或代码直接使用了原生的字符串格式化（`f-string`、`.format()`、`%s`）拼接HTML片段并直接作为HTTP响应体返回。

#### 5. 证伪标准

符合以下任意一条特征，应研判为**误报（False Positive）**：
1. **存在有效的编码/转义:** 污点传播路径上调用了 `html.escape()`、`cgi.escape()` 等标准转义函数。
2. **存在有效的富文本清洗:** 污点传播路径上调用了 `bleach.clean()` 等基于白名单的 HTML 净化函数。
3. **强类型阻断:** 变量在到达 Sink 之前被转化为 `int`、`float`、`uuid.UUID` 等不可能携带恶意脚本的类型。
4. **正则表达式或白名单严格校验:** 数据流经了严格的正则表达式校验（例如仅允许字母和数字 `^[a-zA-Z0-9]+$`），从根本上排除了 `<`、`>`、`'`、`"` 等关键攻击字符。
5. **框架默认保护生效:** 变量直接传入了默认开启 Autoescape 的模板（如标准的 Jinja2 或 Django 模板），且未使用任何取消转义的过滤器或标记。