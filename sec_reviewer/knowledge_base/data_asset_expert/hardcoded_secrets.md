---
cwe_id: ["CWE-798", "CWE-540", "CWE-321"]
name: "Hardcoded_Secrets"
domain: ["Data_Asset_Expert", "General_Expert"]
---

#### 1. 漏洞机制
开发人员将敏感凭据（如API密钥、数据库密码、加密私钥或访问令牌）以明文字符串的形式直接编写在Python源代码中，导致能够访问代码库或反编译程序的实体可以轻易提取并滥用这些凭据进行未授权访问。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
涉及身份认证、授权或密码学操作的核心对象，主要表现为：
- **高危变量/参数命名特征**：包含 `password`, `secret`, `api_key`, `token`, `access_token`, `aws_secret_access_key`, `jwt_secret`, `private_key` 等。
- **高危API调用/库依赖**：认证客户端初始化（如 `boto3.client()`, `pymysql.connect()`, `redis.Redis()`）、HTTP请求凭据（如 `requests.post(auth=...)`）、密码学操作（如 `jwt.encode(key=...)`, `cryptography.fernet.Fernet()`）。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
代码中直接暴露敏感信息的具体写法，例如：
- **直接赋值高熵/结构化明文字符串**：如 `API_KEY = "sk-proj-xxxx..."` 或 `aws_secret = "AKIA..."`。
- **函数调用中的硬编码传参**：将明文字符串直接传入高危API，如 `client = boto3.client('s3', aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')`。
- **配置字典中的硬编码**：在全局配置字典中直接写死生产环境密码，如 `DB_CONFIG = {"host": "prod.db", "password": "ComplexPassword123!"}`。

##### 3. 缺失的安全控制 (Missing Security Controls)
为了满足安全基准，代码中本应存在但缺失的凭据外置与管理措施，例如：
- **缺失环境变量加载机制**：未使用 `os.getenv()`, `os.environ.get()` 或 `pydantic-settings` 等机制动态加载配置。
- **缺失密钥管理系统集成**：未使用 AWS Secrets Manager, HashiCorp Vault, Azure Key Vault 等 KMS 服务的 SDK 动态获取凭据。
- **缺失安全的本地配置文件解析**：未使用 `python-dotenv`, `configparser` 等库去读取被版本控制系统忽略（如加入 `.gitignore`）的本地配置文件。

#### 3. 典型误报样例

- **测试环境与Mock数据**：在 `tests/`, `conftest.py` 或测试类中出现的 `test_password = "test123"` 或用于跑通单元测试的假 Token。
- **占位符文本**：如 `YOUR_API_KEY_HERE`, `change_me`, `<insert_password>`，或全为 `X`、`*` 的掩码字符串。
- **非机密的高熵字符串**：被扫描器误判的文件哈希值（如 `hashlib.md5(b'data').hexdigest()` 的预期对比值）、Git Commit SHA、前端资源的 SRI hash、或者公开的测试向量。
- **公钥与非对称加密的公开部分**：如 `-----BEGIN PUBLIC KEY-----` 开头的证书或公钥字符串。
- **字典的键名而非键值**：如 `os.environ.get("AWS_SECRET_ACCESS_KEY")` 中，字符串本身只是环境变量的 Key，并非真正的 Secret。

#### 4. 证实标准

当满足以下所有条件时，即可研判为真实漏洞（True Positive）：
1. **内容有效性**：硬编码的字符串具有高熵值，或者符合特定云服务商/平台的票据正则格式（如 GitHub 的 `ghp_...`，Slack 的 `xoxb-...`，OpenAI 的 `sk-...`）。
2. **上下文敏感性**：该字符串在代码中被实际用于网络请求、数据库连接、加密签名、解密流程等需要鉴权/保密的上下文。
3. **生产环境倾向**：文件路径和模块命名表明其属于核心业务逻辑或生产配置，而非测试文件、示例模板（如 `.env.example`）或文档。
4. **非占位符特征**：字符串内容不包含明显的占位符语义（如不包含 `dummy`, `test`, `example` 等词根）。

#### 5. 证伪标准

当满足以下任一条件时，即可研判为误报（False Positive）：
1. **环境上下文证伪**：文件路径包含 `test`, `demo`, `example`, `mock`, `doc`，或属于 `.env.example` / `.env.template` 等模板文件。
2. **占位语义证伪**：字符串明显是占位符（如包含 `<...>`, `YOUR_...`, `REPLACE_...`）或是极低熵值的弱密码（在非生产逻辑中，如 `password123` 用于本地 SQLite 测试）。
3. **公有资产证伪**：被标记的字符串实际上是公钥（Public Key）、非对称加密证书（CRT）、或者开源项目中已公开的校验用哈希值（如 MD5/SHA256 file hash）。
4. **语法功能证伪**：被标记的字符串仅仅是用于字典索引、JSON/YAML 解析键名、环境变量名称（例如 `get_secret("MY_DATABASE_PASSWORD")`），而非凭据的值本身。
5. **系统默认值（条件接受）**：代码为本地开发环境设置的开源组件默认账户密码（如 `pymysql.connect(user='root', password='')` 或 `redis.Redis(host='localhost')`），且未暴露公网业务的生产凭据。