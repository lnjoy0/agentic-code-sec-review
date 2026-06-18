---
cwe_id: ["CWE-276"]
name: "Iac_k8s_Misconfiguration"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
容器编排配置文件中未严格限制容器的运行特权、网络隔离、资源配额或安全上下文，导致部署的 Python 应用容器极易被提权、横向移动或遭遇拒绝服务攻击。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
该风险通常存在于项目仓库中的 Kubernetes 资源定义文件（如 `deployment.yaml`、`pod.yaml`、`cronjob.yaml` 等 YAML 文件）或 Helm Charts 模板中。它直接影响在 Kubernetes 集群中运行的 Python Web 应用（如基于 Flask、Django、FastAPI 框架构建的微服务）及其底层容器运行时的安全边界。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
*   **特权与隔离打破：** 显式设置了 `privileged: true`，或将 `hostNetwork: true`、`hostPID: true`、`hostIPC: true` 打开，导致 Python 应用可以直接访问宿主机资源，绕过容器隔离。
*   **高危权限运行：** 未设置 `runAsNonRoot: true` 或将 `runAsUser` 设为 `0` (root)。由于官方 Python 基础镜像（如 `python:3.11`）默认以 root 用户运行，这会导致应用容器在生产环境中继承 root 权限。
*   **凭据硬编码：** 在环境变量 `env` 列表中，以明文形式硬编码传入 Python 应用所需的数据库密码、第三方 API Token 或 Django 的 `SECRET_KEY`，而不是通过 `secretKeyRef` 引用 Secret 资源。
*   **调试边界暴露：** 在 `Service` 或 `Ingress` 配置中，不当地将运行着 Python 交互式调试器（如开启了 `DEBUG=True` 的 Werkzeug 调试面板、或者绑定了 `debugpy` / `ptvsd` 的端口）的容器端口直接暴露给集群外部。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
*   **安全上下文缺失：** 缺失显式的 `securityContext` 限制，未配置 `allowPrivilegeEscalation: false` 以防止子进程提权，以及未配置 `readOnlyRootFilesystem: true` 以锁定根文件系统。
*   **资源配额缺失：** 未限制容器资源（缺失 `resources.limits.cpu` 和 `resources.limits.memory`）。由于 Python 存在全局解释器锁 (GIL) 以及部分第三方库可能存在内存泄露隐患，缺失限制极易导致单个 Pod 耗尽整个宿主机节点的资源。
*   **网络阻断缺失：** 缺乏与之配套的 `NetworkPolicy` 规则。默认情况下 Kubernetes 网络是全通的，若未配置“默认拒绝 (Default Deny)”的网络策略，一旦该 Python Web 服务被攻破，攻击者可在集群内部无阻碍地进行横向探测。

#### 3. 典型误报样例

*   **样例 1：非生产环境配置**
    扫描器在 `tests/`、`dev/` 目录或以 `*-dev.yaml` 命名的文件中发现了未配置安全基线的 Manifest。但经智能体上下文分析，确认该文件仅用于本地 `minikube` 调试或 CI 流程中的临时集成测试，绝不上线生产环境，此时应判定为环境误报。
*   **样例 2：特定的运维/管理脚本容器**
    某一特定的 `CronJob` 运行着使用 `kubernetes-client` (Python SDK) 的集群维护脚本，该脚本确实需要高权限去管理集群资源（如驱逐 Pod、清理孤立资源），因而挂载了高权限的 `ServiceAccount` 且未开启某些严格限制。这属于符合业务设计预期的行为，并非安全漏洞。
*   **样例 3：因业务特性导致无法开启只读文件系统**
    Trivy 告警提示某 Python 应用未设置 `readOnlyRootFilesystem: true`。但系统研判发现，该 Python 应用使用了老旧的框架，在启动时必须在运行目录下动态生成大量的 `.pyc` 字节码缓存文件，或需要向本地写入临时文件，且架构上无法改造为挂载 `emptyDir`。在这种由于运行依赖导致的“无法开启”场景下，应当作误报或可接受风险过滤。

#### 4. 证实标准

当满足以下**全部**条件时，可判定为真实漏洞：
1.  **路径有效性：** 确认存在漏洞特征的 YAML 文件位于生产环境部署路径中（如 `deploy/prod/`、`manifests/live/` ），或属于生产 CI/CD 流水线（如 GitHub Actions）直接引用的配置文件。
2.  **配置实体生效：** 配置文件中缺失关键防护项（如未设置 `runAsNonRoot`）或显式声明了高危项（如 `privileged: true`），且代码仓库中不存在任何集群全局安全策略（如 Kyverno、OPA Gatekeeper 约束文件）对该不安全配置进行拦截或自动修正。
3.  **漏洞可达性：** 容器内运行的确实是 Python 应用程序，且该程序存在暴露于公网的 Service 入口（针对端口暴露漏洞），或者其使用的基础镜像确实是以 root 身份作为默认入口。

#### 5. 证伪标准

当满足以下**任一**条件时，可判定为误报（或可忽略的安全风险）：
1.  **环境隔离：** 文件明确标记为测试、本地开发或 Demo 演示专用，不参与生产构建与发布。
2.  **全局动态补偿机制：** 尽管单个 YAML 中缺失了安全配置，但项目内或部署架构中配置了全局的“变异准入控制器 (Mutating Admission Webhook)”，该控制器会在 Pod 落地到集群时，自动强制注入 `securityContext`、`readOnlyRootFilesystem=true` 等补救字段。
3.  **多层防御覆盖：** 针对网络暴露告警，如果对应的 `Service` 虽然是 `NodePort` 或带有公网 `Ingress`，但上层云环境的 IaC（如 Terraform 脚本）中，在网络安全组 (NSG) 层面已经严格将该端口的入向流量限制在特定的内部 IP 范围内，则可实施证伪。