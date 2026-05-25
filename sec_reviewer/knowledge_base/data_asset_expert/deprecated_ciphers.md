---
cwe_id: ["CWE-327"]
name: "Deprecated_Ciphers"
domain: ["Data_Asset_Expert", "General_Expert"]
---
#### 1. 漏洞机制
代码中使用了已知存在严重安全缺陷或被业界明确废弃淘汰的密码学算法（如 DES、3DES、RC4、Blowfish、MD5、SHA1 等），导致攻击者能够以较低成本通过密码分析、碰撞攻击或暴力破解等方式还原明文或伪造签名，从而破坏数据的机密性与完整性。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
漏洞通常涉及 Python 中主流密码学库的特定类、模块或 API 调用，典型目标包括：
*   **对称/非对称加密模块**：`cryptography.hazmat.primitives.ciphers.algorithms` (PyCA cryptography 库)、`Crypto.Cipher` (PyCryptodome 库)。
*   **哈希/摘要模块**：`hashlib` 标准库、`Crypto.Hash`。
*   **高危 API 标识**：`algorithms.ARC4`, `algorithms.DES`, `algorithms.TripleDES`, `algorithms.Blowfish`, `Crypto.Cipher.DES.new`, `Crypto.Cipher.ARC4.new`, `hashlib.md5`, `hashlib.sha1`。
*   **敏感资产对象**：变量名包含 `password`, `secret`, `token`, `session_id`, `pii`, `credit_card` 等的加密/散列操作。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
代码中直接实例化或调用了已被废弃的算法，导致加密或哈希过程处于不安全状态。典型错误写法：
*   **使用弱对称加密算法**：
    *   `Cipher(algorithms.DES(key), mode=...)` 
    *   `Cipher(algorithms.ARC4(key), mode=None)`
    *   `DES.new(key, DES.MODE_ECB)`
*   **使用弱哈希算法处理敏感数据（如密码存储或签名）**：
    *   `hashlib.md5(password.encode()).hexdigest()`
    *   `hashlib.sha1(auth_token).digest()`
*   **生成长度不足的非对称密钥**：
    *   `rsa.generate_private_key(public_exponent=65537, key_size=1024)` （RSA 密钥长度小于 2048 位）。

##### 3. 缺失的安全控制 (Missing Security Controls)
为了满足现代安全基准，代码中本应采用但缺失的现代密码学替代方案与安全实践：
*   **缺失强对称加密算法**：未使用 AES (如 `algorithms.AES`, `algorithms.AESGCM`) 或 ChaCha20 (`algorithms.ChaCha20`) 替代老旧块/流密码。
*   **缺失抗碰撞的强哈希算法**：未使用 SHA-256 / SHA-3 系列替代 MD5/SHA-1。
*   **缺失专用的密钥派生函数 (KDF)**：在处理密码存储时，缺失 PBKDF2, bcrypt, Argon2 或 scrypt 等专门设计的慢速哈希算法。

#### 3. 典型误报样例

*   **非安全场景的哈希校验**：使用 `hashlib.md5()` 仅用于生成非敏感数据的缓存键 (Cache Key)、计算文件的 checksum 以校验网络传输的偶发损坏（非防篡改校验），或用于简单的去重操作。
*   **遗留数据解密 (只读兼容)**：系统为了读取多年前加密的历史归档数据，显式调用了 `DES` 或 `3DES` 进行**单向解密**，但系统的新数据写入已切换至 AES。
*   **与老旧第三方系统/硬件的通信妥协**：通过 API 或网络协议与不受控的外部遗留硬件设备（如老旧的门禁系统、旧版银行接口）通信，对方强制要求使用 3DES 或 SHA1。
*   **安全测试或蜜罐代码**：代码属于安全测试套件、漏洞 PoC、或蜜罐系统，故意实现了弱加密算法用于演示或捕获攻击。

#### 4. 证实标准

满足以下所有条件即可证实为真实漏洞：
1.  **算法本身属于废弃列表**：明确调用了 DES, 3DES, RC2, RC4, Blowfish, MD2, MD4, MD5, SHA-1 等被 NIST/业界宣告废弃的算法，或使用了长度小于 2048-bit 的 RSA。
2.  **用于安全边界防御**：该算法被直接用于保障数据的机密性（加密 PII/密码/令牌）、完整性（数字签名防篡改）或认证凭据的存储。
3.  **属于当前系统的自主选择**：代码正在对**新生成的数据**进行加密或哈希，且开发者有权限/能力选择更安全的算法，非外部遗留系统强制约束。

#### 5. 证伪标准

满足以下任一条件即可判断为误报（或可接受风险）：
1.  **无安全上下文 (No Security Context)**：弱哈希算法（如 MD5）明确用于文件去重、本地对象标识符、缓存路由键等不涉及防篡改或机密性的功能。
2.  **解密向下兼容 (Legacy Decryption)**：代码逻辑明确表明这只是一个向下兼容的读取层（例如变量名为 `decrypt_legacy_data`），且该算法未被用于加密任何新生成的数据。
3.  **协议/硬件强制约束 (Protocol/Hardware Constraint)**：注释或上下文明确指出由于要对接不受控的遗留第三方系统（如 `legacy_bank_api_des_encrypt`），作为客户端别无选择只能使用该弱算法。
4.  **明确的测试/模拟上下文**：文件路径位于 `tests/`, `mock/` 下，或属于已知用于生成漏洞测试样例的工具代码。