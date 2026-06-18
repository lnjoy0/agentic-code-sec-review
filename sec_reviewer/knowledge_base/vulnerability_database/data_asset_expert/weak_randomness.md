---
cwe_id: ["CWE-338"]
name: "Weak_Randomness"
domain: ["Data_Asset_Expert", "General_Expert"]
---

#### 1. 漏洞机制
在密码学或安全敏感场景（如生成密钥、令牌、会话ID、密码等）中，使用了可预测的、非密码学安全的伪随机数生成器（如 Python 的 `random` 模块），导致攻击者可以通过收集输出序列来推断生成器的内部状态，进而预测未来的“随机”值或还原历史值。

#### 2. 典型漏洞代码样例

##### 1. 敏感资产/操作目标 (Target Assets / Operations)
*   **敏感变量命名特征：** 涉及鉴权、加密或防伪造标识的变量，如 `token`, `session_id`, `password`, `secret_key`, `salt`, `nonce`, `activation_code`, `otp` 等。
*   **高危库函数/API调用：** 导入并使用了非加密安全的标准库，如 Python 内置的 `random` 模块（`random.randint()`, `random.choice()`, `random.random()`, `random.choices()`, `random.getrandbits()`）或第三方科学计算库（如 `numpy.random`）。

##### 2. 缺陷实现与不安全状态 (Defective Implementations / Unsafe States)
*   **直接使用弱伪随机函数生成敏感凭据：**
    ```python
    import random
    # 缺陷：使用 random.choice 生成重置密码的 Token
    def generate_reset_token():
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(32))
    ```
*   **使用可预测的种子（Predictable Seeding）：**
    ```python
    import random
    # 缺陷：使用当前时间戳作为种子，极易被爆破或猜测
    random.seed(int(time.time()))
    session_id = random.getrandbits(128)
    ```

##### 3. 缺失的安全控制 (Missing Security Controls)
*   **缺失密码学安全的伪随机数生成器（CSPRNG）：** 在 Python 环境中，生成安全敏感的随机数本应强制引入并使用 `secrets` 模块或底层的 `os.urandom()`。
*   **缺失的代码替换措施：**
    *   缺失 `secrets.choice(chars)` 替代 `random.choice()`。
    *   缺失 `secrets.token_hex()` 或 `secrets.token_urlsafe()` 替代手动的随机字符串拼接。
    *   缺失 `SystemRandom()`（`random.SystemRandom` 类，底层调用 `os.urandom`）作为 `random` 模块函数的安全替代品。

#### 3. 典型误报样例

扫描器常常无法区分“随机数的使用上下文”，只要检测到 `random` 模块就会告警，以下是典型的非安全场景误报：

*   **场景 1：网络请求重试的抖动退避（Jitter / Exponential Backoff）**
    ```python
    import random
    # 误报：用于防止雪崩效应的随机延迟，与安全性无关
    time.sleep(base_delay + random.uniform(0, 1))
    ```
*   **场景 2：UI/展示层面的乱序或抽样（UI shuffling / Data Sampling）**
    ```python
    import random
    # 误报：打乱列表以在前端随机展示推荐商品
    random.shuffle(recommended_products)
    ```
*   **场景 3：单元测试数据生成（Test Data Generation）**
    ```python
    import random
    # 误报：在测试用例中生成随机的虚拟年龄
    test_user_age = random.randint(18, 65)
    ```
*   **场景 4：非加密强度的游戏逻辑或蒙特卡洛模拟**
    ```python
    import random
    # 误报：游戏中的掷骰子逻辑
    dice_roll = random.randint(1, 6)
    ```

#### 4. 证实标准

当满足以下**所有条件**时，即可研判为真实漏洞（True Positive）：
1.  **明确使用了弱随机源：** 代码实际调用了 `random` 模块或类似非 CSPRNG 库的方法。
2.  **处于安全敏感上下文：** 生成的随机值用于直接或间接影响系统安全性，例如：
    *   用户认证凭据（密码、一次性密码 OTP、验证码）。
    *   会话管理（Session ID、CSRF Token、OAuth State 参数）。
    *   密码学要素（加密密钥、初始化向量 IV、随机盐 Salt、数字签名 Nonce）。
    *   业务安全关键标识（具有防遍历要求的订单号、兑换码、激活码）。
3.  **生成的随机值对外暴露或可被观测：** 攻击者可以通过接口、URL、Cookie 或日志等途径获取到部分生成的随机值，从而具备收集序列以反推随机数种子（如 Mersenne Twister 的内部状态）的条件。

#### 5. 证伪标准

当满足以下**任一条件**时，即可研判为误报（False Positive）：
1.  **非安全敏感上下文：** 随机数仅用于统计模拟、数据抽样、UI 展示打乱、游戏逻辑、网络重试抖动（Jitter）、非安全业务的唯一性去重（且不作为鉴权依据）或测试代码。
2.  **已使用安全的替代方案：** 代码表面上导入了 `random` 模块，但实际调用的是 `random.SystemRandom` 实例（它底层依赖 `os.urandom`，是密码学安全的）。
    ```python
    import random
    # 证伪：SystemRandom 是密码学安全的
    secure_rng = random.SystemRandom()
    token = secure_rng.randint(0, 999999)
    ```
3.  **随机数仅作为强安全机制的次要补充（不作为唯一防御依据）：** 例如生成一个仅用于内部追踪的 TraceID，虽然代码使用了 random，但即使被预测也不会对系统造成实质性的安全越权或数据泄露。