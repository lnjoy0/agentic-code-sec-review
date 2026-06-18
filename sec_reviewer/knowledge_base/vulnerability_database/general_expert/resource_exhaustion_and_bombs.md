---
cwe_id: ['CWE-400', 'CWE-409']
name: 'Resource_Exhaustion_and_Decompression_Bombs'
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制

资源耗尽与解压炸弹：应用程序在处理不受信任的输入（如高压缩比的压缩包或深度嵌套的结构化数据）时，未能有效限制内存分配、磁盘写入量或解析深度，导致攻击者可通过引发非预期的海量资源消耗（如触发解压炸弹或解析巨量冗余数据）来实现系统资源枯竭与拒绝服务（DoS）。

#### 2. 典型漏洞代码样例

```python
import zipfile
import tarfile
from flask import request, Flask

app = Flask(__name__)

@app.route('/upload_plugin', methods=['POST'])
def upload_plugin():
    file = request.files['plugin']
    upload_path = f"/tmp/{file.filename}"
    file.save(upload_path)
    
    # 典型漏洞代码：无任何大小限制直接解压
    extract_dir = "/app/plugins/"
    with zipfile.ZipFile(upload_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
        
    return "Plugin loaded successfully!"
```

##### 1. 业务意图与高风险特性 (Business Intent & High-Risk Features)
代码的原始业务目的通常是接收外部传递的归档文件（如 `.zip`, `.tar.gz`）进行解压以处理内部批量数据，或接收结构化文档（如 XML、YAML）进行对象反序列化。此过程中依赖的高危机制是调用 Python 标准库中默认无限制的解析/解压方法，例如直接使用 `zipfile.ZipFile.extractall()`、`tarfile.extractall()` 将压缩包展开到本地目录，或使用 `xml.etree.ElementTree.parse()` 处理带有外部实体引用的 XML 数据。

##### 2. 威胁面与非预期执行 (Threat Surface & Unsafe Execution)
攻击者可通过构造极高压缩比的恶意载荷（例如：数十 KB 大小但解压后达数 GB 的海量零字节“Zip 炸弹”，或使用 Billion Laughs 攻击构造的 XML 炸弹）作为输入提交给系统。当应用程序执行原生的、无限制的解压或解析逻辑时，非预期的庞大膨胀数据会被直接强行加载到内存或写入磁盘，瞬间突破系统所在容器或宿主机的承载极限，破坏 CIA 三要素中的可用性（Availability），导致当前进程崩溃（OOM）、磁盘写满挂起或 CPU 被长期占用。

##### 3. 缓解措施与资源/边界限制 (Mitigations & Boundary Limits)
为了阻断上述推演的攻击链路，代码中本应存在但缺失的“显性或隐性防御”包括：
* **压缩包解压场景**：
  1. 缺失在解压循环中通过 `ZipInfo.file_size` 累加校验总解压大小的阈值限制（例如超过 100MB 阻断）；
  2. 缺失对压缩比（如解压后大小/压缩前大小 > 100）的异常预警；
  3. 缺失对 `ZipInfo.is_dir()` 嵌套层级和解压文件总数量的限制。
* **数据解析场景**：
  1. 缺失对 XML/YAML 解析器的安全配置限制（例如未使用 `defusedxml` 替代标准 `xml` 库来禁用实体扩展）；
  2. 缺失流式读取（Chunked 流）以及资源枯竭时的超时熔断与异常捕获降级机制。

#### 3. 典型误报样例

```python
import zipfile
import os

MAX_EXTRACT_SIZE = 100 * 1024 * 1024  # 100 MB limit
MAX_FILES = 1000                      # 1000 files limit

def safe_extract_plugin(upload_path, extract_dir):
    with zipfile.ZipFile(upload_path, 'r') as zip_ref:
        extracted_size = 0
        file_count = 0
        
        for zip_info in zip_ref.infolist():
            file_count += 1
            if file_count > MAX_FILES:
                raise ValueError("Too many files in the archive.")
                
            extracted_size += zip_info.file_size
            if extracted_size > MAX_EXTRACT_SIZE:
                raise ValueError("Extracted size exceeds the maximum allowed limit.")
                
            # 仅提取常规文件，防范路径穿越 (此处忽略路径穿越校验细节)
            zip_ref.extract(zip_info, extract_dir)
```

1.  **受信任的数据源**：解压的目标文件并非来自外部用户输入，而是硬编码在代码中的静态资源文件，或者是从可信的内部构建制品库下载的依赖包，攻击者无法控制压缩包内容。
2.  **已实现自定义封装防护**：代码虽然调用了 `extract()`，但并未直接使用危险的 `extractall()`，而是通过自定义的迭代器遍历文件列表，并在每次提取前检查 `file_size` 和总累计大小，实现了有效的阈值拦截。
3.  **安全工具库**：代码导入了 `defusedxml.ElementTree` 或配置了 `yaml.SafeLoader`，底层解析引擎已经天然免疫了实体膨胀炸弹。

#### 4. 证实标准

如果**同时满足**以下条件，智能体系统应研判为**真实漏洞（True Positive）**：
1. **外部可控输入**：压缩文件的来源、复杂嵌套 JSON/XML 等数据流向可追溯到用户外部输入（如 HTTP 请求、第三方不可信队列、用户上传的 S3 桶）。
2. **触发高危 Sink**：数据流进入了消耗系统资源的 API（例如：`zipfile.extractall()`, `tarfile.extractall()`, `xml.etree.ElementTree.parse()` 且未禁用外部实体，或无限增长的 `while/for` 内存追加操作）。
3. **缺乏资源检查前置条件**：在触发 Sink 操作前，没有任何逻辑检查数据的未压缩大小、体积膨胀率、嵌套层数或实体节点数量。
4. **缺乏运行时资源约束**：操作未被包裹在严格的时间超时机制（Timeout）或内存隔离沙箱中。

#### 5. 证伪标准

如果满足以下**任一条件**，智能体系统应研判为**误报 (False Positive)**：
1. **内部可信数据**：输入源为系统内部绝对可控的静态文件（如硬编码路径下的系统默认配置文件、构建时打包的基础资源），外部攻击者无法污染该文件。
2. **显式前置阈值校验**：代码采用迭代式读取/解压，并在每次迭代或解压前，累加计算物理资源消耗量，一旦超过预设定的安全阈值（如校验 `zipinfo.file_size`）立即 `break` 或抛出异常中断执行。
3. **使用了安全的替代库**：例如针对 XML 炸弹（Billion Laughs Attack），代码并未直接使用 `xml.etree.ElementTree`，而是使用了 `defusedxml.ElementTree`，该库已内置对递归实体扩展的默认防护。
4. **硬性容量限制生效**：被审计代码逻辑所处的上下文确保了文件大小不可能达到触发阈值（例如 API 网关层或 Nginx 已经强制限制了 `client_max_body_size` 为 1MB，物理上杜绝了深层高危炸弹的投递，尽管代码层仍不严谨，但实操利用可能性极低，可降级或标记为误报）。