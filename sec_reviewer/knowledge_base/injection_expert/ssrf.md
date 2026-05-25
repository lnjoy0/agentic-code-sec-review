---
cwe_id: ["CWE-918"]
name: "Server-Side_Request_Forgery"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
攻击者通过控制应用程序中发起网络请求的URL或目标地址参数，诱使服务器端以自身的网络身份向受保护的内部网络、外部恶意主机或本地服务发起伪造请求，从而突破网络边界实现信息窃取、内网扫描或执行未授权操作。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
在Python生态中，输入源通常来自Web框架接收的外部参数。
*   **Flask / Werkzeug:** `request.args.get('url')`, `request.form.get('target')`, `request.json.get('webhook')`
*   **Django:** `request.GET.get('url')`, `request.POST.get('target')`, `request.data.get('webhook')`
*   **FastAPI / Starlette:** 路由函数中定义的查询参数（如 `def fetch(url: str):`），或请求体模型（如 `item.url`）

##### 2. 危险执行点 (Sinks)
所有能在Python中发起底层TCP连接或HTTP请求的库和函数。
*   **Requests 库:** `requests.get(url)`, `requests.post(url)`, `requests.request('GET', url)`
*   **标准库 urllib:** `urllib.request.urlopen(url)`, `urllib.request.urlretrieve(url)`
*   **异步 HTTP 客户端:** `aiohttp.ClientSession().get(url)`, `httpx.get(url)`, `httpx.AsyncClient().get(url)`
*   **底层 Socket / 底层连接:** `http.client.HTTPConnection(host)`, `socket.create_connection((host, port))`

##### 3. 传播路径特征
*   **直接透传:** 变量从输入源提取后，未经任何修改或校验，直接作为参数传入 Sink 函数（例如：`url = request.args.get('url'); requests.get(url)`）。
*   **字符串拼接/格式化:** 输入作为URL的一部分被拼接，尤其是控制了 Host 或 Scheme 闭合部分（例如：`target = f"http://{request.args.get('domain')}/api"; requests.get(target)`）。
*   **重定向跟随:** 即使初始验证了URL，但 Sink 函数配置了自动跟随重定向（如 `requests.get(url, allow_redirects=True)`，这是 Requests 的默认行为），且攻击者提供的外部服务器返回指向内网的 30x 响应。

#### 3. 典型误报样例

*   **完全硬编码的 URL:** URL 是在代码中静态定义的，虽然使用了 `requests.get()`，但没有任何外部可控变量输入。
    ```python
    # 误报：完全不受用户控制
    def fetch_internal_config():
        requests.get("[http://10.0.0.5:8080/config](http://10.0.0.5:8080/config)")
    ```
*   **严格的白名单校验 (Allowlist):** URL 或 Host 在发起请求前，经过了严格的硬编码白名单全等匹配。
    ```python
    # 误报：经过严格白名单过滤
    ALLOWED_DOMAINS = {"api.github.com", "api.stripe.com"}
    url = request.args.get('url')
    domain = urllib.parse.urlparse(url).hostname
    if domain in ALLOWED_DOMAINS:
        requests.get(url)
    ```

#### 4. 证实标准

当满足以下**所有**条件时，应研判为**真实漏洞（True Positive）**：
1.  **数据流可达:** 能够清晰追踪到外部可控数据（Source）流向了网络请求函数（Sink）的目标地址参数。
2.  **缺乏有效过滤:** 传播路径中**没有**对目标 URL 的协议（Scheme）、主机名（Hostname）或 IP 地址进行白名单校验；或校验存在明显逻辑缺陷（黑名单极易被绕过）。
    *   *黑名单缺陷示例:* 仅过滤了 `127.0.0.1` 和 `localhost`，但未过滤 `0.0.0.0`, `2130706433` (十进制IP), 或各种 IPv6 的内网表达形式。
    *   *解析差异缺陷:* 使用简单的字符串校验（如 `url.startswith("http://example.com")` 可被 `http://example.com.malicious.com` 绕过）。
3.  **非隔离环境:** 代码未显式说明该请求是在沙箱或强制的 egress proxy（出站代理）网络隔离层中执行。

#### 5. 证伪标准

当满足以下**任意**一项条件时，应研判为**误报（False Positive）**：
1.  **输入不可控:** 传入网络请求 Sink 的变量实际上并非来自外部输入，而是受信任的内部调用流传递的固定值。
2.  **严格的白名单防御:** 在执行网络请求前，对解析出的 Hostname 或 IP 进行了严格的白名单检查（如 `in` 集合匹配，或正确的正则表达式边界匹配）。
3.  **内网 IP 阻断 (DNS层或逻辑层):** 代码包含标准的防 SSRF 解析逻辑：
    *   首先解析 URL 获取 Hostname。
    *   将 Hostname 进行 DNS 解析获取真实 IP。
    *   检查解析出的 IP 是否属于私有地址空间（如 Python 中的 `ipaddress.ip_address(ip).is_private` 或 `is_loopback`）。
    *   使用该已校验的 IP 发起请求，并在请求头中带上原始 Host（防 DNS Rebinding 机制）。