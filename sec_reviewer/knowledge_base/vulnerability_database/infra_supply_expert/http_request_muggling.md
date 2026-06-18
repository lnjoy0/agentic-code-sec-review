---
cwe_id: ["CWE-444"]
name: "HTTP_Request_Smuggling"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
HTTP 请求走私（HRS）：攻击者通过构造同时包含或篡改 `Content-Length` (CL) 和 `Transfer-Encoding` (TE) 头的畸形 HTTP 请求，利用前端网关（代理）与 Python 后端服务器（如 Gunicorn/Uvicorn）对报文边界解析规则的不一致性，将恶意 Payload “夹带”进后续合法用户的请求流中，从而实现越权访问、缓存投毒或绕过前端安全控制。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
在 Python 审计环境中，该漏洞的线索通常存在于：
1. **依赖清单文件**：如 `requirements.txt`, `Pipfile`, `pyproject.toml`，暴露了过时且存在已知边界解析缺陷的 WSGI/ASGI 框架或服务器（如特定低版本的 Waitress, Gunicorn, Uvicorn, aiohttp。
2. **应用服务器启动配置**：如 `gunicorn.conf.py`, `uvicorn` 的启动脚本，涉及 Header 处理或直接对外暴露的设置。
3. **自定义反向代理/中间件代码**：如 FastAPI/Flask/Django 的 Middleware，或基于 `httpx`/`requests` 实现的请求转发器，这些代码拦截并重新拼接 HTTP 报文。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
1. **危险透传与拼接**：在 Python 自定义网关或中间件中，接收到客户端请求后，直接将其 `Headers`（尤其是原封不动的 `Content-Length` 和 `Transfer-Encoding`）透传给下一个内部服务，未对冲突的头部进行清洗。
   * 代码特征：在转发逻辑中出现类似 `requests.post(url, headers=request.headers, data=request.body)` 的粗暴透传。
2. **组件版本脆弱性**：依赖了已被公开披露存在请求走私漏洞的组件（例如：Waitress < 1.4.0 允许包含无效字符的 HTTP 头；Gunicorn 某些版本对 TE 头解析不严谨）。
3. **架构边界暴露**：将主要设计用于后置反向代理之后的纯 Python 应用服务器（如 Werkzeug 默认开发服务器），通过代码或 Docker 暴露在 `0.0.0.0`，直接处理不受信的、未经过滤的复杂公网流量。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
1. **缺失头部冲突校验**：Python 路由或中间件在处理流量时，未校验并拒绝同时包含 `Content-Length` 和 `Transfer-Encoding` 头的非法请求（规范做法应优先使用 TE，或直接抛出 400 错误）。
2. **缺失 Header 规范化（Normalization）**：未能剥离畸形的头字段（如 `Transfer-Encoding: chunked\r\n`，带有空格或其他混淆字符的变体）。
3. **未强制使用安全协议**：后端未配置禁用 HTTP/1.1 连接重用（Keep-Alive），或未使用先天免疫此漏洞的 HTTP/2 协议。

#### 3. 典型误报样例

1. **终端节点（Sink）读取头信息**：扫描器发现代码读取或打印了 `Transfer-Encoding` 或 `Content-Length`（如用于日志记录或文件大小限制校验），但该 Python 服务是请求的最终处理节点，并未将其作为代理向下游转发。由于不存在“前后端解析不一致”的上下文，不构成走私条件。
2. **纯内网且无代理的 RPC 调用**：微服务之间在受信的内网环境中通过 HTTP/gRPC 直连交互，调用链路上完全不存在反向代理或负载均衡器。
3. **测试代码与 Mock**：在 `tests/` 目录下，用于测试解析器鲁棒性而人工构造的包含畸形头部的单元测试代码。
4. **已被更外层框架阻断**：代码虽然透传了所有的 Header，但该 Python 程序的上游（如强制绑定的 Nginx 或 WAF）已经配置了严格的请求规范化或直接丢弃了冲突报文。

#### 4. 证实标准

满足以下**全部条件**时，可判定为真实漏洞：
1. **存在脆弱逻辑或组件**：代码中存在自定义的、未清洗 HTTP 请求头的反向代理/转发逻辑，**或**依赖文件中明确引入了存在请求走私 CVE 的 Python Web 服务器版本。
2. **具备走私利用路径**：代码允许在单个 TCP 连接上处理多个连续的 HTTP 请求（支持 HTTP Keep-Alive），并且未对包含冲突头部（同时存在 CL 和 TE，或多重 TE 头）的报文进行阻断或规范化。
3. **架构上下文吻合**：该 Python 服务在实际运行环境中，前端必须存在至少一个反向代理/网关/负载均衡器（形成代理与后端服务器的串联拓扑）。

#### 5. 证伪标准

满足以下**任一条件**时，可判定为误报：
1. **无代理架构**：该 Python 应用程序明确只作为单机工具、离线脚本使用，或直接面向客户端暴露，前端没有任何代理/网关组件（不会发生基于代理差异的走私）。
2. **无转发行为（非网关类应用）**：代码仅作为数据处理终点，没有将接收到的 HTTP 请求体与头部二次拼接并转发给其他内部服务的逻辑。
3. **明确的防御/拒绝逻辑**：Python 代码或中间件中存在明确的安全拦截机制（例如：一旦检测到 `Transfer-Encoding` 包含不合规字符，或与 `Content-Length` 同时存在，立即返回 `HTTP 400 Bad Request` 并主动关闭连接）。
4. **组件版本安全**：所使用的 Python Web 服务器组件（如 Gunicorn, Uvicorn, Waitress 等）版本高于已知的请求走私漏洞修复版本，且使用的是默认或安全的连接配置。