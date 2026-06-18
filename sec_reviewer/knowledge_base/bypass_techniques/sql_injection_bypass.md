---
name: "SQL_Injection_Bypass_Techniques"
---

#### 1. 弱黑名单与关键字清洗
当专家发现开发者试图通过 `replace()`、正则替换或简单的黑名单来剔除危险字符（如 `'`, `SELECT`, `UNION`, 空格）时，此类防御极其脆弱。
* **Code特征:** 使用 `replace('SELECT', '')`、正则 `re.sub(r'(?i)union', '', input)` 或自定义的黑名单拦截器。
* **绕过Payload/机制:**
  * **双写绕过 (Double-Writing):** 针对一次性替换的逻辑，输入 `SELSELECTECT`，中间的 `SELECT` 被替换为空后，两端字符恰好重组为 `SELECT`。
  * **大小写与编码变异:** 针对未开启全局忽略大小写的校验，使用 `SeLeCt` 绕过；或者使用 Hex 编码（如 `0x73656c656374`）、Unicode 编码规避字面量检查。
  * **等价符号/函数替换:**
    * 过滤了空格？使用 `/**/` (行内注释)、`%0a` (换行)、`%09` (Tab)、`() `包裹来替代。
    * 过滤了 `=`？使用 `LIKE`, `REGEXP`, `IN` 或 `<>` 替代。
    * 过滤了 `SUBSTR()`？使用 `MID()`, `RIGHT()`, `LEFT()` 替代。

#### 2. 无法参数化的特定子句（动态拼接）
预编译（参数化查询，如 `?` 或 `%s`）只能用于替换 SQL 语句中的**数据值（Values）**，无法替换**表名**、**列名**或**排序关键字**。
* **Code特征:** 业务涉及动态排序（`ORDER BY`）、动态表名或列名查询。开发者被迫退化为使用 f-string 或字符串拼接（例如：`f"SELECT * FROM users ORDER BY {sort_col}"`）。
* **风险特征** 只要在 `ORDER BY`、`GROUP BY` 或表名处存在外部输入的拼接，就存在**盲注风险**。
  * **攻击方法:** 攻击者可以利用 `(CASE WHEN ... THEN ... ELSE ... END)` 结构或 `IF()` 函数进行**时间盲注**或**布尔盲注**。
    * *盲注Payload样例:* `sort_col=(CASE WHEN (SUBSTR(version(),1,1)='8') THEN sleep(5) ELSE id END)`
  * **研判重点:** 必须检查拼接前是否存在严格的**白名单映射**或**强类型限制**。例如：
    * *白名单映射:* `if sort_col not in ['id', 'username', 'created_at']: sort_col = 'id'`
    * *字典映射:* `safe_columns = {"1": "id", "2": "name"}; actual_col = safe_columns.get(user_input)`

#### 3. ORM / Query Builder 原生查询方法误用
现代开发广泛使用 ORM，但为了处理复杂查询，开发者常调用 ORM 提供的“原生 SQL 接口”。此时如果混入未清洗的变量，ORM 的保护机制将彻底失效。
* **Code特征与脆弱样例:**
  * **Django:** 使用了 `extra(where=[...])` 或 `RawSQL` 并直接拼接变量。
      * `User.objects.extra(where=[f"name = '{user_input}'"])`
  * **SQLAlchemy:** 误用 `text()` 进行直接拼接。
      * `session.query(User).filter(text(f"status = '{user_status}'")).all()`
* **专家研判标准:** 审计 ORM 代码时，必须警惕任何包含 `raw`、`text`、`extra`、`query` 等字眼的函数，并检查其内部是否安全使用了框架提供的绑定参数机制，而非原生字符串插值。

#### 4. 二次注入 (Second-Order Injection)
攻击并非发生在数据“输入”的那一刻，而是发生在数据被“再次提取使用”时。
* **漏洞机制:** 攻击者在第一步（如注册）将恶意 Payload（如用户名 `admin' --`）通过安全的手段（ORM或参数化）存入数据库。第二步，后台脚本从数据库读出该脏数据，并**未经校验地**拼接进新的 SQL 语句中（如修改密码：`f"UPDATE users SET pwd='{new}' WHERE user='{db_user}'"`），此时单引号闭合，引发注入。
* **专家研判标准:** 追踪数据流时，**绝不能只盯着外部 HTTP 请求源**（如 `request.GET`）。数据库自身的查询结果、Redis 缓存数据、日志文件，都可能是被污染的 Source。

#### 5. 不完备的转义与宽字节注入
* **反斜杠 (`\`) 逃逸:** 
  * **Code特征:** 开发者仅使用 `replace("'", "\\'")` 替换单引号，却忽略了对反斜杠 `\` 自身的转义。
  * **漏洞机制:** 攻击者传入用户名为 `\`，密码为 ` OR 1=1 -- `。拼接后语句变为 `WHERE user='\' AND pass=' OR 1=1 -- '`。注意：`user` 字段的尾部单引号被反斜杠转义了，导致字符串一直延续到 `pass` 的开头单引号才闭合，从而使得后续的 `OR 1=1` 成为独立语句被执行。
* **宽字节注入 (GBK):**
  * **Code特征:** 数据库连接字符集设置为多字节（如 `GBK`），且应用层使用了类似PHP `addslashes()` 的单字节转义逻辑（如自定义的转义函数）。此时转义逻辑会将 `'` (即 `%27`) 变成 `\'` (`%5c%27`)。
  * **绕过Payload:** 攻击者传入 `%df%27`。转义后变成 `%df%5c%27`。在 GBK 解析时，`%df%5c` 被合并解析为一个中文字符（如“運”），从而“吃掉”了转义符 `\`，使得尾随的单引号 `%27` 成功逃逸。

#### 6. 框架类型欺骗 (Type Confusion)
利用 Web 框架自动解析 JSON 的特性，向预期接收“字符串”的变量注入“列表 (List)”。
* **Code特征:** 开发者依赖 `isinstance(var, str)` 来决定是否执行安全清洗（如转义单引号），却在后续直接将该变量拼接入 SQL 语句。
* **脆弱代码样例:**
    ```python
    value = request.json.get('username') # 预期 value 是字符串，例如 "admin"   
    if isinstance(value, str):
        value = value.replace("'", "''") 
    query = f"SELECT * FROM users WHERE username = '{value}'"
    ```
* **绕过机制与研判:** 
  * **Payload:** 攻击者传入 JSON 数组 `{"username": ["admin' OR 1=1 --"]}`。
  * **隐式转换逃逸:** 由于传入的是 List，`isinstance(str)` 返回 False，**完美跳过单引号转义**。而在最后一行拼接时，Python 隐式调用 `str(list)`，将其变成原样的字符串：`["admin' OR 1=1 --"]`。
  * **最终 SQL 语句:** `SELECT * FROM users WHERE username = '["admin' OR 1=1 --"]'`。注意：`admin` 后面的单引号成功吃掉了前面的包裹引号，导致 `OR 1=1` 直接执行！