---
cwe_id: ["CWE-328", "CWE-327"]
name: "Weak_Hashing_Algorithms"
domain: ["Data_Asset_Expert", "General_Expert"]
---

#### 1. 漏洞机制
在处理密码存储、数字签名或敏感数据防篡改等需要高抗碰撞性或抗暴力破解的安全场景中，使用了如 MD5、SHA1 等已被证明存在碰撞漏洞，或计算速度过快（易受彩虹表/字典攻击）的哈希算法。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
* **高危库函数/API调用**：Python 标准库中的 `hashlib.md5()`, `hashlib.sha1()`, `hashlib.new('md5')`；或第三方密码学库如 `cryptography.hazmat.primitives.hashes.MD5()`。
* **敏感上下文与变量特征**：涉及的目标数据或变量命名通常包含 `password`, `pwd`, `secret`, `token`, `signature`, `auth`, `credential`, `pin` 等与认证、授权或防篡改直接相关的词汇。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
* **直接对凭据使用弱哈希**：将明文敏感数据直接传入弱哈希函数并持久化，例如直接调用 `hashlib.md5(password.encode()).hexdigest()` 保存用户密码。
* **滥用快速哈希存储密码**：即使是 SHA-256/SHA-512 等目前尚未被攻破的算法，如果未经多轮迭代和加盐直接用于**密码存储**，由于现代 GPU 计算速度极快，仍属于缺陷实现。
* **自定义且脆弱的消息认证**：试图通过简单的字符串拼接实现防篡改验证（例如 `hashlib.md5(secret + data).hexdigest()`），这种实现易受长度扩展攻击（Length Extension Attack）。

##### 3. 缺失的安全控制 (Missing Security Controls)
* **缺失慢速密钥派生函数（KDF）**：在密码存储场景中，缺失 `bcrypt`, `argon2`, `scrypt` 等慢速哈希算法的使用，或未调用标准库中的 `hashlib.pbkdf2_hmac`。
* **缺失高熵随机盐（Salt）**：缺失利用 `secrets` 模块（如 `secrets.token_bytes()`）为每个用户/操作生成唯一且随机的盐值。
* **缺失标准消息认证码（MAC）**：在数据完整性与来源校验场景中，缺失对标准 HMAC 机制的调用（如 `hmac.new(key, msg, digestmod=hashlib.sha256)`）。

#### 3. 典型误报样例

```python
import hashlib

def get_cache_key(sql_query: str) -> str:
    # 误报：用于生成系统内部缓存的键值，无关加密或机密性
    return hashlib.md5(sql_query.encode('utf-8')).hexdigest()

def generate_gravatar_url(email: str) -> str:
    # 误报：对接第三方服务（Gravatar），该协议硬性要求使用 MD5 散列邮箱
    email_hash = hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()
    return f"[https://www.gravatar.com/avatar/](https://www.gravatar.com/avatar/){email_hash}"

def check_file_duplicate(file_path: str) -> str:
    # 误报：仅用于识别重复文件（文件特征指纹），不涉及防篡改或机密性防御
    # 且在 Python 3.9+ 明确标记了 usedforsecurity=False 意图
    with open(file_path, 'rb') as f:
        return hashlib.md5(f.read(), usedforsecurity=False).hexdigest()
```

#### 4. 证实标准

必须同时满足以下三个条件，智能体方可判定为真实漏洞：
1. **算法弱性确认**：代码中确实调用了 MD5、SHA1 等弱哈希算法，或在认证凭据存储场景中使用了非迭代的快速哈希。
2. **数据敏感性确认 (Source)**：被哈希的数据属于安全敏感资产（如用户密码、会话 Token、支付相关签名、身份凭证）。
3. **安全意图确认 (Sink/Context)**：使用该哈希的目的是为了满足机密性（防止数据泄露后的逆向工程）或完整性（防篡改验证），而当前所选算法的抗碰撞/抗爆破能力无法支撑此目的。

#### 5. 证伪标准

只要代码满足以下任意一项特征，智能体应判定为误报（False Positive）：
1. **明确的非安全用途**：上下文（变量名、函数名、注释）清晰表明，哈希仅用于数据分布（如一致性哈希槽）、生成唯一标识（如 UUIDv3）、内存对象比对、缓存键（Cache Key）生成或非敏感的文件去重。
2. **外部第三方协议/系统硬性约束**：调用的外部 API 或既定工业标准强制要求使用 MD5/SHA1（例如对接微信支付老版本的 MD5 签名、S3 桶的 ETag 校验），且开发者无权变更该协议。
3. **显式声明非安全用途**：在 Python 3.9+ 环境中，调用处明确传递了 `usedforsecurity=False` 参数，且经过跨函数数据流分析，该哈希值未被投入任何安全防御流程。
4. **向下兼容的降级验证**：代码虽然包含弱哈希逻辑，但仅用于验证历史遗留旧格式的密码；且在验证通过后，代码会自动使用强哈希（如 bcrypt）重写存储（密码升级机制）。