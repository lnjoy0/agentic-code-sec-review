---
cwe_id: ["CWE-1336"]
name: "SSTI"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
SSTI（Server-Side Template Injection）：攻击者能够将恶意构造的输入直接作为模板内容的一部分，注入到服务端模板引擎（如 Jinja2、Mako、Django Templates 等）中并被解析执行，从而导致敏感信息泄露、沙箱逃逸或远程代码执行（RCE）。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
在 Python Web 框架中，典型的不可信输入源主要来源于 HTTP 请求的各个部分：
```python
# Flask / Werkzeug
user_input = request.args.get('name')
user_input = request.form.get('name')
user_input = request.cookies.get('session')
user_input = request.headers.get('User-Agent')

# Django
user_input = request.GET.get('name')
user_input = request.POST.get('name')

# FastAPI / Starlette
user_input = request.query_params.get('name')
```

##### 2. 危险执行点 (Sinks)
执行点是各模板引擎中动态解析字符串为模板的函数或类实例化过程：
```python
# Flask / Jinja2
from flask import render_template_string
import jinja2
flask.render_template_string(user_input)
jinja2.Template(user_input).render()
jinja2.Environment().from_string(user_input).render()

# Django Templates
from django.template import Template, Context
Template(user_input).render(Context({}))

# Mako
from mako.template import Template
Template(user_input).render()

# Tornado
from tornado.template import Template
Template(user_input).generate()
```

##### 3. 传播路径特征
典型的漏洞路径特征是：不可信数据未经严格过滤，直接通过字符串拼接或格式化的方式，构成了模板的主体（Template Payload），然后送入 Sink。
```python
# 特征：字符串拼接后作为模板主体渲染
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 传播路径：Source (name) -> 字符串格式化 (template_str) -> Sink (render_template_string)
    template_str = f"<h1>Hello, {name}!</h1>" 
    return render_template_string(template_str)
```

#### 3. 典型误报样例

智能体在扫描时极易将安全的上下文变量传递误报为 SSTI 漏洞。

**误报样例 1：作为上下文变量传入**
```python
@app.route('/safe_greet')
def safe_greet():
    name = request.args.get('name', 'Guest')
    # 输入作为变量传入模板，引擎会自动对其进行转义和安全处理，这是标准且安全的用法
    return render_template_string("<h1>Hello, {{ user_name }}!</h1>", user_name=name)
```
**误报样例 2：渲染静态文件**
```python
@app.route('/profile')
def profile():
    name = request.args.get('name', 'Guest')
    # render_template 渲染的是本地静态 .html 文件，输入仅作为变量传入
    return render_template('profile.html', user_name=name)
```
**误报样例 3：输入被严格限制或类型转换**
```python
@app.route('/user/<int:user_id>')
def user_info(user_id):
    # user_id 已被框架强制转换为整型，无法构造 SSTI Payload
    template_str = f"<h1>User ID: {user_id}</h1>"
    return render_template_string(template_str)
```

#### 4. 证实标准

当满足以下全部条件时，应研判为**真实漏洞（True Positive）**：
1. **数据流连通:** 存在一条清晰的 Taint 数据流，从不可信的输入源（Source）流向模板渲染函数（Sink）。
2. **污染模板主体:** 不可信数据直接参与了模板字符串本身的构建（例如被传入 `render_template_string` 的第一个参数），而不是作为 `kwargs`（上下文变量）传递。
3. **缺乏有效净化:** 在数据到达 Sink 之前，没有经过强制类型转换（如 `int()`）、严格的正则白名单校验或 HTML 实体转义机制（需要注意的是，简单的 XSS 过滤函数无法防御 SSTI，因为 SSTI payload 如 `{{7*7}}` 并不依赖 `<script>` 等 HTML 标签）。

#### 5. 证伪标准

符合以下任意一条特征，应研判为**误报（False Positive）**：
1. **上下文传递模式:** 用户输入仅仅作为模板渲染函数的上下文参数（Context Variables / Kwargs）传入，模板本体是静态的、硬编码的字符串。
2. **静态文件渲染:** 使用的是渲染静态文件的函数（如 Flask 的 `render_template`），且被渲染的文件路径或文件名不受用户控制。
3. **有效阻断/强类型化:** 数据流在到达执行点前，被强制转换为安全类型（如布尔值、整型），或者通过了严格的枚举/正则白名单校验（例如仅允许 `[a-zA-Z0-9]+`）。
4. **常量覆盖:** 变量在声明后、到达 Sink 前，被重新赋值为安全的常量或不可控的静态数据，导致 Taint 链断裂。