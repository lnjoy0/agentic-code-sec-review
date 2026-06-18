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