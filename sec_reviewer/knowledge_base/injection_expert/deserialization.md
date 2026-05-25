---
cwe_id: ["CWE-502"]
name: "Deserialization_of_Untrusted_Data"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
应用程序在将不可信的序列化数据（如来自网络请求、用户输入或外部未授权修改的文件）还原成Python对象时，由于没有进行严格的安全校验或使用了不安全的解析方法，导致攻击者可以通过精心构造的恶意序列化载荷在目标服务器上执行任意代码、读取敏感文件或引发拒绝服务。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
*   **Web请求参数与正文：** `request.data`, `request.args.get()`, `request.form`, `request.cookies.get()` (例如：Flask/Django/FastAPI接收的输入)。
*   **消息队列与RPC通信：** Celery、RabbitMQ、Redis等消息代理中接收的外部不受控消息。
*   **外部文件上传：** 用户上传的 `.pkl`, `.pickle`, `.yaml`, 或机器学习领域的模型权重文件（如 `.pt`, `.pth`）。
*   **数据库/缓存读取：** 从外部应用可控的Redis、Memcached或数据库中直接读取并反序列化的数据。

##### 2. 危险执行点 (Sinks)
*   **Pickle/Shelve/Marshal系列：** 
    *   `pickle.loads(data)` / `pickle.load(file)`
    *   `cPickle.loads(data)`
    *   `shelve.open(filepath)`
    *   `marshal.loads(data)`
*   **YAML解析：**
    *   `yaml.unsafe_load(data)`
    *   `yaml.load(data, Loader=yaml.Loader)`
    *   `yaml.load(data, Loader=yaml.UnsafeLoader)`
*   **第三方反序列化库：**
    *   `jsonpickle.decode(data)`
    *   `jsonpickle.unpickler.decode(data)`
*   **数据科学与机器学习生态（底层封装了Pickle）：**
    *   `pandas.read_pickle(filepath_or_buffer)`
    *   `torch.load(f, weights_only=False)` (PyTorch模型加载)
    *   `numpy.load(file, allow_pickle=True)`

##### 3. 传播路径特征
*   **编码转换：** 攻击者载荷常经过 Base64 编码或 Hex 编码传输，传播路径中常出现 `base64.b64decode(user_input)` -> `pickle.loads()` 的组合。
*   **解压缩处理：** 载荷可能被压缩，出现 `zlib.decompress(data)` -> `pickle.loads()`。
*   **直接透传：** 框架路由函数接收参数后，未经过滤直接传递给上述 Sink 执行点。

#### 3. 典型误报样例

**误报样例 1：反序列化完全受信任的本地文件**
```python
# 扫描器可能会因为看到了 pickle.load 而告警，但实际上文件路径是硬编码的内部可信资源
def load_config():
    with open('/app/internal/default_config.pkl', 'rb') as f:
        return pickle.load(f)
```
**误报样例 2：安全的反序列化方法**
```python
import yaml
import json
def parse_data(user_input):
    # 误报：使用了 safe_load 或纯粹的 json.loads，不会执行任意代码
    data1 = yaml.safe_load(user_input) 
    data2 = json.loads(user_input)
    return data1, data2
```
**误报样例 3：执行反序列化前进行了密码学签名校验**
```python
from itsdangerous import URLSafeSerializer
def decode_cookie(cookie_data):
    # 误报：虽然最终进行了反序列化，但在还原之前通过 HMAC 校验了数据的完整性和来源
    serializer = URLSafeSerializer('secret-key')
    try:
        # 如果数据被篡改，此处会抛出 BadSignature 异常，不会进入底层危险解析
        return serializer.loads(cookie_data)
    except Exception:
        return None
```

#### 4. 证实标准

当以下所有条件均满足时，Agent应将此告警判定为**真实漏洞（True Positive）**：
1. **触达危险 Sink:** 数据流最终进入了已知的不安全反序列化函数（如 `pickle.loads`, `yaml.unsafe_load`, `torch.load(weights_only=False)` 等）。
2. **源头可控（Tainted Source）:** 被反序列化的数据直接或间接来源于不受信任的外部输入（HTTP请求、外部上传的文件、未校验的数据库字段等）。
3. **缺乏校验:** 在数据到达 Sink 之前，没有使用密码学签名（如 HMAC）验证数据的完整性和来源，也没有使用严格的白名单机制限制可反序列化的类。

#### 5. 证伪标准

当满足以下任意一个条件时，Agent应将此告警判定为**误报（False Positive）**：
1. **来源绝对可信（Safe Source）:** 传递给 Sink 的数据完全由系统内部生成或硬编码，外部攻击者无法修改（例如加载代码库自带的静态配置文件、加载预置且受保护的 ML 模型权重）。
2. **Sink 是安全的:** 虽然扫描器告警了反序列化相关的库，但实际调用的是安全的方法（如 `yaml.safe_load()`, `ast.literal_eval()`, `json.loads()`, `torch.load(..., weights_only=True)`）。
3. **强签名验证拦截:** 数据源虽然来自外部（如 Cookie），但在执行反序列化之前，使用了强密码学签名机制（如 Django 的 `Signer`，`itsdangerous` 库）进行验签，且密钥未泄露。
4. **使用了安全的自定义 Unpickler:** 开发者重写了 `pickle.Unpickler` 的 `find_class` 方法，且实现了严格的白名单，只允许反序列化良性的、无执行危害的数据类（Data Classes）。