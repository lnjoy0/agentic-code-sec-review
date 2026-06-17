---
cwe_id: ["CWE-89"]
name: "SQL_Injection"
domain: ["Injection_Expert", "General_Expert"]
---

#### 1. 漏洞机制

SQL注入漏洞源于应用程序未对不可信的外部输入进行有效的清洗或参数化处理，便将其直接以字符串拼接或格式化的方式动态构造进SQL语句并提交数据库执行，导致攻击者能够利用注入的SQL控制字符篡改原有查询的语法逻辑，进而实现越权的数据访问、篡改或更深层的破坏。

#### 2. 漏洞代码样例

##### 1. 典型输入源 (Sources)
不可信数据通常来源于网络请求参数、API载荷、命令行参数或读取到的外部文件等。
*   **Flask / Werkzeug:** `request.args.get()`, `request.form.get()`, `request.json`, `request.headers.get()`
*   **Django:** `request.GET.get()`, `request.POST.get()`, `request.headers`
*   **FastAPI / Starlette:** 路由参数 (`@app.get("/{user_id}")`), 查询参数 (`Query()`), 请求体 (`Body()`)
*   **其他:** `sys.argv`, `os.getenv()` (若环境变量被用户控制)

##### 2. 危险执行点 (Sinks)
接受SQL语句并提交给数据库执行的函数或方法。
*   **PEP 249 DB-API (sqlite3, psycopg2, PyMySQL等):** `cursor.execute(query)`, `cursor.executemany(query, ...)`
*   **SQLAlchemy:** `session.execute()`, `engine.execute()`, `connection.execute()` (当传入未经参数化处理的字符串时)
*   **Django ORM:** `Model.objects.raw(query)`, `cursor.execute(query)`, `Model.objects.extra(where=[...])`

##### 3. 传播路径特征
污点数据从 Source 流向 Sink 的过程中，经历了能够改变SQL语义的字符串操作。
*   **f-string 拼接:** `query = f"SELECT * FROM users WHERE username = '{user_input}'"`
*   **`.format()` 方法:** `query = "SELECT * FROM users WHERE id = {}".format(user_id)`
*   **`%` 格式化:** `query = "SELECT * FROM users WHERE username = '%s'" % user_input`
*   **字符串相加:** `query = "SELECT * FROM users WHERE username = '" + user_input + "'"`

#### 3. 高级绕过技巧

在进行漏洞研判时，专家极易被代码中“似是而非”的保护机制欺骗。必须牢记以下红队绕过思维：

##### 1. 黑名单替换
开发者常使用 `replace()` 或正则匹配来剔除危险字符（如 `'`, `SELECT`, `UNION`, 空格）。
* **双写绕过 (Double-Writing):** 针对 `replace('SELECT', '')` 的防御，输入 `SELSELECTECT`，经过一次替换后恰好组合成真正的 `SELECT`。
* **大小写变异:** 针对未开启不区分大小写标志的正则匹配，使用 `SeLeCt`、`uNiOn` 绕过。
* **等价函数与符号替换:**
    * 不用空格：使用 `/**/` (行内注释), `%0a` (换行), `%09` (Tab), `%0b` (垂直制表符) 替代。
    * 不用 `=`：使用 `LIKE`, `REGEXP`, `IN` 或 `<>` 替代。
    * 不用 `SUBSTR()`：使用 `MID()`, `RIGHT()`, `LEFT()` 替代。

* **JSON/Unicode 编码逃逸:** 前端传入 JSON 载荷 `{"name": "admin\u0027 or 1=1--"}`，可以绕过基于字符串字面量的简单 WAF，而到达后端被 Python `json.loads()` 解析后，单引号 `\u0027` 会被还原为 `'` 并参与拼接。

##### 2. 无法参数化的特定子句
预编译（参数化查询）只能用于替换 SQL 语句中的**数据值**，无法替换**表名、列名**或**排序关键字**。如果业务需要动态排序或动态表查询，开发者极易退化回字符串拼接。
* **绕过技巧:** 即便开发者限制了不能出现 `SELECT`、`UNION` 等关键字，只要此处存在拼接，攻击者就可以利用 `(CASE WHEN ... THEN ... ELSE ... END)` 结构或 `IF()` 函数进行**时间盲注**或**布尔盲注**。
* **代码样例:**
    ```python
    # 表面似乎安全，其实攻击者可以执行盲注
    order_by = request.args.get('sort', 'id')
    # 攻击者输入: sort=(CASE WHEN (SUBSTR(version(),1,1)='8') THEN sleep(5) ELSE id END)
    query = f"SELECT * FROM products ORDER BY {order_by}" 
    ```

##### 3. ORM 原生查询方法误用
现代 Web 开发大量使用 ORM，但复杂的查询往往逼迫开发者使用 ORM 提供的“原生 SQL 接口”。这些接口如果混入未清洗的变量，ORM 的保护机制将形同虚设。
* **Django 的 `extra()` 和 `RawSQL`:**
    ```python
    # 危险代码：extra 的 where 参数本质是直接拼接 SQL
    user_input = request.GET.get('name')
    User.objects.extra(where=[f"name = '{user_input}'"]) 
    ```
* **SQLAlchemy 的 `text()` 误用:**
    ```python
    # 危险代码：虽然用了 ORM，但 text() 内部直接 f-string 拼接
    from sqlalchemy import text
    user_status = request.json.get('status')
    session.query(User).filter(text(f"status = '{user_status}'")).all()
    ```

##### 4. 二次注入
攻击者在第一步（如注册、修改资料）将包含SQL注入Payload的恶意数据通过“安全的手段（如ORM或参数化）”存入数据库。在第二步，系统后台或其他业务逻辑从数据库读出该脏数据，并**未经校验地**拼接进新的SQL语句中触发执行。
* **攻击示例:** 攻击者在注册用户名时输入 `admin' --`，入库时被安全处理（数据库中存的就是 `admin' --`）。但后台脚本在修改密码时执行了：`f"UPDATE users SET password='{new_pwd}' WHERE username='{db_user_name}'"`，此时单引号闭合，引发严重注入。
* **研判视角:** 不要只盯着外部 HTTP 输入源（如 `request.GET`）。数据库自身的查询结果、缓存系统（Redis）读取的数据、日志文件，都可能是被污染的 Source。

##### 5. 不完备的清洗与宽字节注入
* **反斜杠 (`\`) 逃逸:** 当开发者仅针对单引号 `'` 进行了转义，却忽略了对反斜杠 `\` 的过滤时。攻击者可以通过输入反斜杠来“吃掉”后面的闭合引号，使用更后面的引号来闭合字符串，从而执行后续语句。
    ```python
    username = request.form.get('user').replace("'", "\\'") # 仅转义了单引号
    password = request.form.get('pass').replace("'", "\\'")
    # 攻击者可以传入 `user = \` 和 `pass =  OR 1=1 -- `，拼接后语句变为 `... WHERE user='\' AND pass=' OR 1=1 -- '`，后面的 OR 语句被执行
    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
    ```
* **宽字节注入 (GBK):** 当数据库连接使用了多字节字符集（如 `GBK`），且应用层使用了类似PHP `addslashes()` 的单字节转义逻辑（如自定义的转义函数）时。
  * **脆弱机制:** 转义逻辑会将 `'` (即 `%27`) 变成 `\'` (`%5c%27`)。
  * **绕过方式:** 攻击者传入 `%df%27`。转义后变为 `%df%5c%27`。在 GBK 编码中，`%df%5c` 会被数据库解析为一个中文字符（如“運”），从而吃掉了反斜杠 `%5c`，使得后面的单引号 `%27` 成功逃逸。

##### 6. 框架类型欺骗
利用现代Web框架（如 FastAPI, Flask, Django）解析请求的特性。开发者期望接收一个字符串并使用正则过滤，但攻击者传入了一个数组或 JSON 对象。
*   **脆弱代码:**
    ```python
    # 开发者预期 id 是一个形如 "1,2,3" 的字符串
    user_ids = request.json.get('ids') 
    if isinstance(user_ids, str) and not re.match(r'^[\d,]+$', user_ids):
        return "Error"
    # 如果攻击者在 JSON 中传入一个列表: {"ids": [1, 2, "3) OR 1=1 --"]}
    # isinstance(user_ids, str) 会返回 False，从而绕过正则检查！
    
    # 最终拼接时，列表被隐式或显式转换为字符串，导致注入
    query = f"SELECT * FROM users WHERE id IN ({str(user_ids).strip('[]')})"
    ```

#### 3. 典型误报样例

启发式扫描器或正则匹配极易将安全的字符串拼接误报为SQL注入。

**误报样例 1：拼接的变量是硬编码的常量或受信任的内部变量**
```python
# 误报：虽然使用了 f-string，但 table_name 是内部不可控常量
def count_records(cursor):
    table_name = "sys_users" 
    query = f"SELECT COUNT(*) FROM {table_name}"
    cursor.execute(query) # Safe
```

**误报样例 2：变量经过了强制类型转换**
```python
# 误报：用户输入经过了严格的类型转换，无法注入SQL控制字符
def get_user_by_id(cursor):
    user_id = int(request.args.get('id', 0)) # 强转为整数
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query) # Safe
```

**误报样例 3：表名/列名的动态拼接（配合白名单）**
```python
# 误报：表名和列名无法使用占位符，但代码实现了严格的白名单校验
ALLOWED_COLUMNS = ['username', 'email', 'created_at']
def get_sorted_users(cursor):
    sort_by = request.args.get('sort')
    if sort_by not in ALLOWED_COLUMNS: # 白名单校验
        sort_by = 'created_at'
    
    query = f"SELECT * FROM users ORDER BY {sort_by} DESC"
    cursor.execute(query) # Safe
```

#### 4. 证实标准

当且仅当满足以下所有条件时，确认为**真实漏洞（True Positive）**：
1. **Source可控:** 存在明确的外部输入点，且攻击者可以自由控制该输入的值。
2. **Sink触达:** 数据最终流入了数据库执行函数（如 `cursor.execute()`）。
3. **不安全拼接:** 从 Source 到 Sink 的控制流或数据流中，发生了直接的字符串拼接或格式化（如 `+`, `%`, `f""`, `.format()`），而非使用参数绑定。
3. **无有效净化:** 在拼接发生前，数据没有经历有效的清洗措施（如强类型转换、严格的正则过滤、安全的转义函数或白名单校验）。

#### 5. 证伪标准

当满足以下任意条件时，应标记为**误报（False Positive）**：
1. **参数化查询:** 危险函数（Sink）的入参正确使用了数据库驱动或ORM支持的占位符机制，并将变量分离作为参数传入。
2. **数据不可控:** 参与SQL语句拼接的变量源头是硬编码常量、配置文件常量或内部环境生成的UUID，外部用户无法操控。
3. **类型收敛安全:** 变量在拼接到SQL语句之前，被强制转换为了安全类型（例如被 `int()`, `float()`, `bool()` 处理过）。
4. **有效白名单:** 必须使用动态拼接的场景（如表名、字段名、ORDER BY子句），其拼接变量被限制在预定义的严格白名单字典或列表中。
5. **ORM抽象拦截:** 调用的是ORM的安全API（如Django的 `.filter(name=user_input)`，SQLAlchemy的 `.where(User.name == user_input)`），底层已自动完成参数化防御。