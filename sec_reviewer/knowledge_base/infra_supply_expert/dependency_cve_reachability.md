---
cwe_id: ["CWE-937"]
name: "Dependency_CVE_Reachability"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
应用程序不仅在依赖清单中引入了含有已知安全漏洞（CVE）的Python第三方库，且在业务逻辑中实际调用了该库中存在漏洞的具体函数、类或API，形成了从应用层输入到第三方漏洞触发点的实质性执行路径（可达性）。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
漏洞通常由跨越文件边界的两部分载体共同构成：
1. 在依赖声明文件（如 `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`）中锁定或引入了受CVE影响版本的第三方包。
2. 在第一方Python源码（`*.py`）的业务逻辑、视图函数或任务流中，通过 `import` 或 `from ... import ...` 引入了该包，并影响了应用的生产运行环境。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
危险特征表现为：
1. 第一方代码明确调用了第三方包中存在缺陷的具体模块或方法（例如：不仅引入了旧版 `PyYAML`，还直接调用了危险的 `yaml.load(data, Loader=yaml.Loader)` 而非 `safe_load`；或调用了受 CVE 影响的 `urllib3` 特定请求构造方法）。
2. 当代码边界被打破，将未经充分清洗的外部变量或用户控制的载荷作为参数传递给这些被污染的API时，即构成了实质性的边界暴露。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
规范的防御基线应当包含：
1. 在依赖配置文件中将存在漏洞的库升级到安全版本并严格锁定版本号（如使用 `pip-compile` 生成带哈希校验的 requirements）。
2. 当因破坏性更新（Breaking Change）无法直接升级时，缺失的基线表现为：在调用该第三方函数前，未补充针对漏洞触发条件的上下文过滤机制（如缺乏参数白名单校验、未禁用危险配置位），或未将高危依赖的执行环境进行沙箱隔离。

#### 3. 典型误报样例

1. **死代码/幽灵依赖 (Dead Code / Ghost Dependency)**：Trivy 在 `requirements.txt` 中扫描出了高危版本的 `requests`（如存在特定CVE），但业务代码仅使用了其 `get()` 方法，而该CVE的触发点实际上位于 `requests.auth` 等完全未被应用引用的子模块中。
2. **不可达的数据流 / 安全参数绑定**：第一方代码确实调用了包含漏洞的第三方函数，但传递给该函数的参数是硬编码常量，或完全由服务端内部生成的安全数据组成（如 `yaml.load("key: value_hardcoded", ...)`），攻击者无法从外部注入恶意 payload 触发漏洞。
3. **测试/开发环境依赖隔离**：带有漏洞的包（如旧版 `pytest` 插件或 `black`）仅存在于 `requirements-dev.txt` 或 `[tool.poetry.group.dev.dependencies]` 中，且应用的 Dockerfile 或 CI/CD 部署脚本明确排除了这些依赖，漏洞代码不会进入生产环境。
4. **应用层已实现缓解措施 (Mitigated by Wrapper)**：开发者虽然调用了易受攻击的API，但在调用链路的上一层已经使用严格的正则匹配、类型转换或自定义 Wrapper 过滤了特定的危险字符，破坏了CVE漏洞利用所需的有效载荷结构。

#### 4. 证实标准

智能体在研判扫描结果时，若发现同时满足以下核心条件（条件4视特定CVE的利用要求可选），应判定为真实漏洞（True Positive）：
1. **版本命中确认**：解析 PR 增量涉及的（或全局的）依赖配置文件，确认当前引入的包版本明确落在目标 CVE 所声明的受影响版本区间内。
2. **控制流可达 (Control-Flow Reachability)**：通过 AST 语法树或调用图分析，确认第一方 Python 代码不仅导入了该库，且明确执行了**触发该CVE所需特定功能**的子模块、类或方法。
3. **触发条件吻合**：第一方代码调用第三方 API 时，所使用的参数配置、Flag 位或运行上下文，完全符合 CVE 漏洞报告（如 NVD 描述或 PoC）中要求的触发条件。
4. **数据流受控 (Data-Flow Controllability) （可选，针对需要输入载荷的CVE）**：对于注入类或反序列化类等需要外部载荷触发的第三方 CVE，存在清晰的数据流传播路径，证明外部可控输入（如 Flask/FastAPI 路由参数、上传的文件、外部API响应）可以不经安全清洗地传递至该第三方漏洞函数的敏感参数中。

#### 5. 证伪标准

智能体在研判扫描结果时，若发现以下情况之一，应判定为误报（False Positive）：
1. **组件/模块未激活（仅导入无调用）**：第一方代码仅在文件头部进行了全局 `import`，或调用了该库的其他安全子模块，但在实际执行流中从未触碰并调用存在漏洞的具体目标函数。
2. **参数环境绝对安全（无污染源）**：调用的受影响函数仅接受应用程序硬编码的安全常量（如 `yaml.load("key: hardcoded_value")`），没有任何一条控制流能将不受信任的外部数据传递给该函数，攻击者无法注入恶意载荷。
3. **运行基线与环境先决条件不匹配**：该 CVE 的触发有严格的环境先决条件（例如仅影响 Windows 系统下的路径解析，或仅在 Python 3.8 以下的特定 C 扩展中触发），而当前审查的代码明确运行在不满足这些条件的基准环境（如基于 Ubuntu Linux 的 Python 3.10 容器）中。
4. **纯开发/测试期依赖（生命周期隔离）**：受影响的库被严格限制在开发测试阶段（如仅存在于 `requirements-dev.txt` 或 `[tool.poetry.group.dev.dependencies]`），且部署配置（如 Dockerfile）明确排除了这些依赖，漏洞代码绝对不会进入生产运行环境。
5. **应用层已实现缓解措施 (Mitigated by Wrapper)**：开发者虽然调用了易受攻击的 API，但在调用的前置路径上已经使用了严格的正则验证、类型强转、或安全的 Wrapper 代理，从根本上破坏了 CVE 漏洞利用所需的特定载荷结构或触发条件。