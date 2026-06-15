---
cwe_id: ["CWE-829"]
name: "Dependency_Confusion"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
依赖混淆漏洞是指在构建或部署阶段，由于包管理器（如 pip）同时暴露于公共软件源和私有软件源且缺乏严格的命名空间与包源绑定机制，攻击者通过在公共源（如 PyPI）发布同名且版本号更高的恶意包，欺骗系统默认按最高版本号优先原则下载并执行恶意代码的供应链攻击机制。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
此漏洞主要存在于 Python 项目的依赖声明与包管理配置文件中，包括但不限于 `requirements.txt`、`pip.conf` (`~/.config/pip/pip.conf` 或 `/etc/pip.conf`)、`setup.py`、`Pipfile`、`pyproject.toml`，以及定义构建/部署过程的 `Dockerfile` 和 CI/CD 脚本（如 `.gitlab-ci.yml`、`GitHub Actions` 工作流）。其影响范围通常是全局系统、容器内部环境或构建流水线所在的运行器，一旦被利用即直接导致环境失陷与代码执行。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
最典型的危险配置是在安装依赖时错误地合并了公共信任域和私有信任域。例如，在 `pip install` 命令或 `pip.conf` 中使用了 `--extra-index-url` 指定私有仓库（如 `pip install --extra-index-url https://nexus.internal/repository/pypi/simple -r requirements.txt`），这会打破私有包的解析边界，导致 pip 同时在 PyPI 和私有仓库中搜索包；由于 pip 默认采用“版本号最高者优先”的策略，攻击者只要在 PyPI 上发布版本号极高（如 `99.99.99`）的同名包，就能覆盖内部的合法依赖。此外，在 `Pipfile` 中定义了多个 `[[source]]` 却未在包依赖项中显式指定 `index`，也会引发此类边界失效。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
为了防御此风险，安全的基线配置应当补充：
- **哈希锁定机制**：如未使用 `--require-hashes` 参数并结合包含包哈希值的锁定文件（类似 `Pipfile.lock` 或 `poetry.lock` 的机制）来校验包的身份。
- **严格的源隔离**：应当使用完全代理且具备命名空间拦截规则的私有仓库作为唯一的 `--index-url`，而非使用 `--extra-index-url` 混合双源。
- **显式源绑定或直连引入机制**：如未采用 PEP 508 规范的直接 URL 引用形式 `package @ git+ssh://...` 或内部包明确绑定内网 index。

#### 3. 典型误报样例

1. **内部名称已被抢占保护**：扫描器发现同时使用了官方源和私有源，但项目所使用的所有私有包名称（如 `mycompany-core-utils`）实际上已经由企业安全团队在公共 PyPI 上注册为无害的占位符空包（Name Squatting）。
2. **全局哈希校验**：虽然使用了 `--extra-index-url`，但 `requirements.txt` 中所有包（包括内部包）均严格附带了 `--hash` 参数，即使外部存在高版本同名包，也会因为哈希不匹配而导致安装失败并阻断攻击。
3. **唯一的代理源**：代码或 CI/CD 脚本中仅配置了单一的 `--index-url` 指向企业内部的 Artifactory 或 Nexus，扫描器错误地将此当做漏洞；实际上该代理服务器内部配置了路由规则，严格禁止内部命名空间的包向上游 PyPI 代理查询。
4. **直连地址安装**：私有依赖没有通过包名加版本号的方式安装，而是直接使用了私有 Git 仓库地址或本地文件路径（例如 `pip install git+https://github.com/org/repo.git`），这种方式不经过 index 索引查询，不存在混淆可能。

#### 4. 证实标准

智能体在研判扫描结果时，若发现同时满足以下全部条件，则应证实为真实漏洞（True Positive）：
1.  **多源混合暴露**：配置中允许包管理器同时从受控的私有源和不受控的公共源（如 PyPI）搜索依赖（典型如使用 `--extra-index-url`，或未关闭默认 PyPI 的情况下添加了私有源）。
2.  **存在私有包引用**：项目的依赖清单中，显式声明了仅存在于组织内部且未在公共 PyPI 上注册防抢注的私有包名称。
3.  **缺乏哈希强校验**：目标环境在安装依赖时，未启用或未全面覆盖哈希校验机制（如未使用 `--require-hashes` 或对应的 `*.lock` 文件）。
4.  **未显式绑定单一源**：未使用包管理器的相关机制（如 Poetry 的 explicit source 策略）将私有包名严格限制为仅从私有源下载。

#### 5. 证伪标准

智能体在研判扫描结果时，若发现以下情况之一，应判定为误报（False Positive）：
1.  **全局源强隔离**：项目使用 `--index-url` 完全替换了默认源，且指向的私有包管理平台具有拦截内网包名向公网透传解析的安全策略。
2.  **哈希强校验生效**：项目对所有依赖（包括间接依赖）均启用了严格的哈希校验与锁定机制，任何未经审计的外部高版本篡改包均无法完成安装。
3.  **无内部私有包**：项目引入的所有依赖均是常规的开源公共依赖，不存在内部自研包，因此不存在被同名抢注混淆的攻击面。
4.  **包级源精准绑定**：通过高级包管理工具（如 `poetry` 或带有特定插件的 `pipenv`）将私有包名称与特定的私有源地址进行了严格的硬绑定，解析该包时不会向公网源发出查询。