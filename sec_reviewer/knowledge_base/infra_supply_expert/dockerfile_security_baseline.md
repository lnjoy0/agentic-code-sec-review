---
cwe_id: ["CWE-250", "CWE-269", "CWE-1188"]
name: "Dockerfile_Security_Baseline_Violations"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
Dockerfile 编写时未遵循最小权限原则和供应链安全规范（如默认使用 root 用户运行 Python 进程、全局权限过载、在镜像层中硬编码敏感信息，或无限制地拷贝构建上下文），导致容器运行时极易遭受权限提升、数据泄露及环境劫持。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
该类漏洞主要存在于 Python 项目根目录或部署目录下的 `Dockerfile`、`docker-compose.yml` 及 `.dockerignore` 文件中。它直接影响应用打包后的容器内部运行环境，同时也可能因为挂载卷或网络配置不当，影响宿主机或容器编排集群（如 Kubernetes）的全局系统安全。通常涉及 Python 基础镜像选择、依赖安装阶段（`pip install`）及最终 WSGI/ASGI 服务（如 gunicorn, uvicorn）的启动阶段。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
在 Python 项目的 Dockerfile 中，边界被打破或产生危险暴露的典型特征包括：
*   **越权执行：** 整个 Dockerfile 缺少 `USER` 指令，导致 Python 进程（如 FastAPI/Django 容器）默认以 `root` (UID 0) 运行，一旦出现 RCE 漏洞，攻击者即刻获取容器最高权限。
*   **上下文过度暴露：** 使用 `COPY . /app` 且未配置 `.dockerignore`，或 `.dockerignore` 缺失对 `.git/`、`.env`、`venv/`、`__pycache__/` 等包含敏感信息或环境冲突目录的拦截。
*   **层级敏感信息硬编码：** 在 `ENV` 或构建参数 `ARG` 中硬编码了真实环境的数据库密码或 API Key（如 `ENV AWS_ACCESS_KEY_ID=AKIA...`），这些信息会永久固化在镜像层（History）中，可通过 `docker inspect` 或镜像解包轻易提取。
*   **危险的文件系统权限：** 构建时使用类似 `RUN chmod -R 777 /app` 的指令，导致容器内任意用户均可篡改 Python 代码或静态资源。
*   **不安全的依赖拉取：** 针对 Python 包使用了 `pip install --trusted-host` 绕过 TLS 校验，或使用 `curl -sSL http://example.com/install.sh | python3` 执行不受信任的远程脚本。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
为了防御此类风险，规范的 Python Dockerfile 应当补充以下基线：
*   **缺失非特权用户切换：** 应当在构建末尾创建并切换至非 root 用户，例如：`RUN useradd -m appuser && chown -R appuser /app` 配合 `USER appuser`。
*   **缺失哈希与版本锁定：** Python 基础镜像应锁定 SHA256 摘要（如 `FROM python:3.11-slim@sha256:abcd...`），`pip install` 应配合 `requirements.txt` 和 `--require-hashes` 进行依赖哈希校验，防止供应链投毒。
*   **缺失多阶段构建 (Multi-stage Build)：** 在编译含 C 扩展的 Python 包时（需 gcc 等工具），未将编译环境与运行环境分离，导致最终镜像包含冗余的构建工具，增大了攻击面。
*   **缺失明确的上下文过滤：** 必须强制配套包含 `.git`、`.env`、`secrets/` 的 `.dockerignore` 文件。

#### 3. 典型误报样例

*   **多阶段构建中的 Builder Root 误报：** 扫描器告警 Dockerfile 使用了 root 用户，但该告警发生在多阶段构建的 `builder` 阶段（需要 root 权限通过 `apt-get install` 安装系统级依赖库编译 Python 包），而最终执行阶段的镜像已正确使用 `USER appuser` 进行权限降级。
*   **占位符环境变量误报：** 扫描器匹配到 `ENV DB_PASSWORD=...` 并告警硬编码凭证，但人工研判发现代码为 `ENV DB_PASSWORD="change_me_in_production"` 或空字符串，这只是为了让 Python 应用（如 Pydantic Settings）在无外部输入时能在 CI 测试中正常初始化的占位符。
*   **精准 COPY 引发的缺失 ignore 误报：** 扫描器告警缺失 `.dockerignore` 文件，但 Dockerfile 中并未使用全量拷贝 `COPY . /app`，而是采用了白名单精确拷贝，如 `COPY requirements.txt ./` 及 `COPY src/ ./src/`，此时 `.dockerignore` 的缺失并不构成实际的安全风险。
*   **测试镜像/沙箱容器环境：** 该 Dockerfile 的命名为 `Dockerfile.test` 或明确用于本地测试的 `docker-compose.override.yml`，其中挂载了本地目录或为了方便 Debug 而未限制权限，这类文件不会被发布到生产环境。

#### 4. 证实标准

满足以下任一条件即可判定为真实漏洞：
*   **Root 运行确认：** 检查 Dockerfile 的最终交付阶段，在 `CMD` 或 `ENTRYPOINT` 指令之前，**未出现任何** `USER` 指令，或明确指定了 `USER root`。
*   **敏感文件打包确认：** Dockerfile 包含 `COPY . <dest>` 或 `ADD . <dest>`，且当前 PR 仓库中不存在 `.dockerignore` 文件，或者该文件内未包含对 `.env`, `*.pem`, `*.sqlite3` 等已知敏感文件的排除声明。
*   **真实硬编码凭据确认：** `ENV` 或 `ARG` 设定的变量值符合高熵值的 token 格式（如真实的 JWT、云厂商 AK/SK），且没有明显的占位符标识。
*   **过度赋权确认：** 在应用运行时所需的文件目录上（如 Python 源码目录），明确执行了 `chmod 777`，且运行进程与文件所有者分离。

#### 5. 证伪标准

满足以下任一条件即可判定为误报：
*   **存在合规的权限降级：** 目标阶段（Target Stage）在启动 Python 主进程（如 `CMD ["gunicorn", ...]`）之前，已正确声明并切换到了非特权用户（如 `USER www-data` 或 `USER 1000:1000`）。
*   **安全的白名单拷贝机制：** 虽然无 `.dockerignore`，但使用了严格的逐个文件拷贝策略（如仅拷贝 `.py` 源码文件夹和依赖清单），物理上隔绝了上下文敏感文件的泄露。
*   **环境变量由外部覆盖或仅为桩数据：** 被告警的硬编码 Secret 值明显是本地开发默认值（如 `test`, `dummy`, `123456`），或代码逻辑证明它强制要求运行时必须由外部注入（如 docker run -e）覆盖后才可运行。
*   **非生产环境：** 该 Dockerfile 或配置明确标识为单元测试、CI 测试容器或本地 Debug 专用（如 `Dockerfile.dev`），不参与生产环境打包。