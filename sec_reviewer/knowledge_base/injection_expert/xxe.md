---
cwe_id: ["CWE-611"]
name: "XXE"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制
XXE（XML_External_Entity_Injection），应用程序在解析不受信任的XML输入时，未禁用外部实体（External Entities）和文档类型定义（DTD）的加载，导致攻击者可通过构造恶意的XML载荷读取服务器本地文件、发起服务器端请求伪造（SSRF）或执行拒绝服务攻击（DoS）。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
在Python Web环境中，输入源通常是接收客户端未经清洗的XML字节流或字符串的框架原生对象：
*   **Flask/Werkzeug**: `request.data`, `request.get_data()`, `request.stream.read()`
*   **Django**: `request.body`
*   **FastAPI/Starlette**: `Request.body()`, `Request.stream()`
*   **文件上传**: 用户上传并被服务端读取的 `.xml`, `.svg`, `.docx`, `.xlsx` 等包含XML结构的文件内容 (`file.read()`)。

##### 2. 危险执行点 (Sinks)
使用了不安全的XML解析库或进行了不安全的解析器实例化配置：
*   **lxml 库 (最常见)**:
    ```python
    from lxml import etree
    # 显式开启了实体解析或网络请求
    parser = etree.XMLParser(resolve_entities=True, no_network=False) 
    etree.parse(xml_input, parser)
    etree.fromstring(xml_input, parser)
    ```
*   **Python原生 xml 库 (原生库存在多种XML漏洞风险，官方文档明确声明对恶意数据不安全)**：
    ```python
    import xml.etree.ElementTree as ET
    import xml.dom.minidom
    import xml.sax
    ET.parse(xml_input)
    ET.fromstring(xml_input)
    xml.dom.minidom.parseString(xml_input)
    xml.sax.parseString(xml_input, handler)
    ```

##### 3. 传播路径特征
1.  从API路由（如 `@app.route`）接收 HTTP POST Body。
2.  数据流未经清洗（未进行DTD过滤或实体剥离），可能经历了简单的字符串拼接或编码转换（如 `.decode('utf-8')`）。
3.  数据作为第一个参数直接流入危险执行点（Sinks）中的解析函数。
4.  （可选）解析后的XML节点文本内容被提取并作为HTTP响应返回，或用于后续的文件操作/数据库查询（这构成了带回显的XXE，盲打XXE不需要此步骤）。

#### 3. 典型误报样例

扫描器极易将以下安全模式误报为漏洞：
**使用了安全的替代库 (`defusedxml`)**
    ```python
    import defusedxml.ElementTree as ET
    ET.fromstring(user_input) # 安全：defusedxml 默认防御XXE和Billion Laughs
    ```
**lxml 解析器已显式禁用实体和网络**
    ```python
    from lxml import etree
    # 安全：显式关闭了漏洞特性
    safe_parser = etree.XMLParser(resolve_entities=False, no_network=True)
    etree.fromstring(user_input, parser=safe_parser)
    ```
**无外部污染源 (内部硬编码或受信数据)**
    ```python
    # XML内容是硬编码的配置字典生成的，或者读取的是系统本地受绝对信任的配置文件
    internal_xml = "<config><theme>dark</theme></config>"
    etree.fromstring(internal_xml) # 误报：输入不可控
    ```

#### 4. 证实标准

智能体需在代码中追踪并确认以下两条逻辑链同时成立，方可判定为**真阳性（True Positive）**：
1.  **数据流可控性（Taint Analysis）**：存在一条清晰的数据流，从外部输入（如Web请求的body、用户上传的文件）无害化处理地流向了XML解析函数。
2.  **解析器脆弱性（Sink Configuration）**：
    *   目标代码使用了原生 `xml` 库（如 `xml.etree.ElementTree`, `xml.sax`, `xml.dom.minidom`）处理上述受污染数据。
    *   或者目标代码使用了 `lxml`，且其 `XMLParser` 的参数中 `resolve_entities` 未被显式设置为 `False`（在较旧版本中默认可能为True），或者被明确设置为 `True`。

#### 5. 证伪标准

如果智能体在代码上下文中发现以下任意一种情况，应将其判定为**误报（False Positive）**：
1.  **库替换**：导入并使用了 `defusedxml` 包下的任何解析函数来替代原生 `xml` 或 `lxml`。
2.  **安全配置拦截**：AST（抽象语法树）特征显示，`lxml.etree.XMLParser` 的实例化参数中明确包含 `resolve_entities=False`（防止本地文件读取）且无其他引发SSRF的配置。
3.  **污染源阻断**：传入 `parse` 或 `fromstring` 的变量，其溯源结果指向硬编码字符串、仅受运维人员控制的本地配置文件，或在进入解析前经过了严格的白名单校验/结构重组（例如先被解析为非XML格式再序列化）。