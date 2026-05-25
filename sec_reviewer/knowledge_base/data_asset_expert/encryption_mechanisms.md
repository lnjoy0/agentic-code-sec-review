---
cwe_id: ["CWE-327", "CWE-329", "CWE-1204", "CWE-780"]
name: "Encryption_Mechanisms"
domain: ["Data_Asset_Expert", "General_Expert"]
---
#### 1. 漏洞机制
在对称或非对称加密过程中未能正确配置密码学机制与工作模式，如对称加密中使用了缺乏扩散性的模式（如 ECB）或静态 IV，以及非对称加密中使用了脆弱的填充方案（如无填充的 Textbook RSA 或易受 Bleichenbacher 攻击的 PKCS#1 v1.5），导致系统易受篡改、选择密文攻击（CCA）或密文填塞（Padding Oracle）攻击。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
核心对象主要为 Python 中主流密码学库的对称与非对称加密对象实例化与调用，特征如下：
- **对称加密核心调用**：`cryptography.hazmat.primitives.ciphers.Cipher`、`Crypto.Cipher.AES.new` (PyCryptodome)。参数特征为 `mode`、`iv`、`nonce`。
- **非对称加密核心调用**：`public_key.encrypt()`、`private_key.decrypt()`，以及对应的填充机制模块 `cryptography.hazmat.primitives.asymmetric.padding`、`Crypto.Cipher.PKCS1_v1_5`。
- **敏感数据载体**：加密操作涉及的机密变量，如 `plaintext`、`secret_token`、`session_key`、`user_data` 等。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
- **非对称加密使用了脆弱的填充模式**：在调用 RSA 加密时，将填充参数显式指定为 `padding.PKCS1v15()`（在 `cryptography` 库中）或使用了 `Crypto.Cipher.PKCS1_v1_5.new()`。这使得密文容易受到选择密文攻击（CCA），攻击者可通过多次构造密文并观察服务器的解密响应来还原明文。
- **无填充的非对称加密 (Textbook RSA)**：完全没有使用填充机制直接进行模幂运算。这种确定性加密无法隐藏明文模式，且极易受到小公钥指数攻击或广播攻击。
- **对称加密使用了不安全的工作模式**：显式指定了 ECB 模式（如 `modes.ECB()` 或 `AES.MODE_ECB`）。由于相同的明文块会生成相同的密文块，无法提供语义安全。
- **静态/硬编码的 IV 或 Nonce**：将对称加密的初始化向量写死为常量（如 `iv = b'0000000000000000'`），导致相同明文在多次加密后产生相同的密文，在 CTR/GCM 模式下甚至会导致灾难性的密钥流恢复。
- **未认证的对称加密机制**：在不可信环境中传输密文时，仅使用了 CBC、CTR 等模式，但未配合 MAC（消息认证码）进行完整性验证。

##### 3. 缺失的安全控制 (Missing Security Controls)
- **缺失非对称加密的 OAEP 填充**：为了抵御 CCA 攻击，RSA 加密本应使用最优非对称加密填充，如 `padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`，但代码中缺失或降级使用了 PKCS#1 v1.5。
- **缺失动态的 IV/Nonce 生成机制**：代码中本应存在但缺失基于强随机数的初始化机制（如使用 `os.urandom(16)` 每次加密动态生成 IV）。
- **缺失认证加密（AEAD）模式**：本应使用自带完整性校验的工作模式（如 `modes.GCM()` 或 ChaCha20-Poly1305），代码却回退使用了基础模式且未手动添加 HMAC 校验。

#### 3. 典型误报样例

1. **历史协议兼容与老旧规范要求**：在对接 SAML、早期的 JWT（JSON Web Token）或遗留的银行/网关接口时，规范本身强制要求使用 RSA PKCS#1 v1.5 进行加密或签名。代码中可能出现 `PKCS1v15()`，但这是为了业务互通性做出的妥协。
2. **测试环境代码**：位于 `tests/` 目录中，为了测试旧版本客户端兼容性或验证特定的解密异常捕获逻辑，故意使用了 ECB 模式或写死的 IV 向量。
3. **数字签名的合规使用**：扫描器匹配到了 `padding.PKCS1v15()`，但数据流表明它被用于 `private_key.sign()` 或 `public_key.verify()`（数字签名场景），而不是 `encrypt()/decrypt()`。虽然签名场景推荐 PSS，但 PKCS#1 v1.5 在签名（如 RS256）中并不存在像 Bleichenbacher 那样致命的解密 Oracle 漏洞，通常被视为可接受或低危（除非被严格的现代基线禁止）。
4. **单区块/高熵数据的 ECB 加密**：使用 ECB 模式加密恰好只有一个数据块长度且自身具备高熵特性的数据（如密钥封装 Key Wrapping 场景，加密另一个 128-bit 密钥），此时 ECB 缺乏扩散性的弱点不会被利用。

#### 4. 证实标准

专家智能体需结合上下文数据流分析，满足以下其一即可证实：
1. **非对称填充缺陷证实**：追踪 `padding.PKCS1v15()` 或 `PKCS1_v1_5` 对象，确认其最终被传入了非对称加密对象的 **`encrypt()` 或 `decrypt()`** 方法，且被加密的明文具有机密性要求（如对称密钥、会话 Token）。
2. **对称模式缺陷证实**：确认传递给对称加密库的 mode 参数确实为 ECB，且被加密的明文长度不可控、可能超过单个 Block Size，或者明文包含具备结构化特征的业务数据（如 JSON、XML）。
3. **IV/Nonce 静态化/重用证实**：确认 `iv` 或 `nonce` 溯源至全局常量，或在一个批量处理/网络请求循环的外部被初始化，导致多个不同的加密操作复用了同一个 IV，且该密文流向了不可信边界（如写入文件、网络发送）。
4. **缺乏完整性校验证实**：发现使用了非 AEAD 的对称加密模式（如 CBC），且业务逻辑中涉及“解密外部输入的密文”，但解密前没有任何 HMAC 或数字签名的合法性校验逻辑，存在密文填塞（Padding Oracle）风险。

#### 5. 证伪标准

专家智能体若发现以下情况，应判定为扫描器误报：
1. **非生产环境证明**：目标代码路径表明其属于测试用例（如 `test_crypto.py`）、Mock 桩代码，或是构建阶段的临时数据混淆（不涉及真实业务安全）。
2. **明确的第三方协议对接声明**：代码上下文（如函数名 `decrypt_legacy_payload`，或 PR 描述/代码注释）明确指出，采用 PKCS#1 v1.5 或 ECB 等不安全机制是为了对接无法更改的第三方老旧系统，且当前系统处于受协议强制约束的状态。
3. **用于签名的 PKCS#1 v1.5**：数据流回溯表明，`PKCS1v15` 仅用于验证数字签名（Verify）或生成数字签名（Sign），而没有被用于数据加解密（Encrypt/Decrypt）。
4. **存在独立的完整性校验 (Encrypt-then-MAC)**：虽然底层使用了非认证的 CBC 模式，但分析外层逻辑发现，开发者已经规范地实现了 Encrypt-then-MAC 流程，在解密操作触发前，已经通过了安全的 HMAC 验证。