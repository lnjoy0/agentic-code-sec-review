---
cwe_id: ["CWE-488"]
name: "JWT_and_Async_Context_Leakage"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
在Python异步并发环境（如FastAPI、Tornado等）中，由于误用全局变量、类级别属性、或使用了非协程隔离的存储（如`threading.local`）来缓存JWT解析后的当前用户身份，导致不同并发请求（协程）之间的上下文发生数据竞争与覆盖，从而引发越权访问。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
漏洞通常发生在异步 Web 框架的中间件（Middleware）、依赖注入函数（Dependencies）或拦截器中。在这些入口点，系统从 HTTP 请求头（如 `Authorization: Bearer <token>`）中提取并验证 JWT，随后将解析出的身份信息（如 `user_id`, `role`）赋值给一个生命周期超出了当前请求范围的变量。典型的危险上下文包括：
- 模块级别的全局变量（`global current_user`）。
- 单例模式或全局依赖注入对象的类属性（`self.current_user = payload.get("sub")`）。
- 在纯 `asyncio` 环境中错误地使用了为同步多线程设计的 `threading.local()`。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
在身份被写入危险上下文后，后续的具体业务逻辑（如在 Service 层或 DAO 层）不再从原生的 `request` 对象中获取用户信息，而是直接读取上述的全局或共享状态。
- **目标动作**：利用读取到的受污染的 `user_id` 执行 ORM 数据库查询（如 `User.filter(id=current_user.id)`）、发起内部微服务的 RPC 调用、或进行越权的数据更新与删除。由于协程的并发交替执行特性，此时读取到的 `user_id` 极可能是另一个并发请求的用户的 ID。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
- **缺失请求作用域隔离**：代码缺失了将状态严格绑定到当前请求生命周期的机制。本应使用 ASGI 框架原生的请求状态存储（如 FastAPI/Starlette 的 `request.state.user`），或 Python 原生的协程安全上下文变量（`contextvars.ContextVar`）。
- **缺失不可变约束**：对于依赖注入的类，未实施无状态（Stateless）约束，导致处理并发请求时实例属性被不断重写。

#### 3. 典型误报样例

1. **正确使用了 `contextvars.ContextVar`**：SAST 工具可能会将 `user_ctx = contextvars.ContextVar("user")` 识别为全局变量，并将其 `.set()` 方法标记为危险写入。实际上，`ContextVar` 在 `asyncio` 中是协程安全的，这是标准的防御做法。
2. **赋值给框架原生请求对象**：向 `request.state.user` (FastAPI/Starlette) 或 `request.ctx.user` (Sanic) 赋值。SAST 工具可能误认为 `request` 是个全局共享对象，但框架底层已保证其与当前 HTTP 请求严格绑定。
3. **函数参数显式传递**：JWT 解析后，身份信息仅仅赋值给了一个局部变量，并通过函数参数（Arguments）一层层显式传递给底层 DAO。扫描器可能因为调用链过长而误报上下文泄露。
4. **多实例类的属性赋值**：在依赖注入中，如果类是 **每次请求动态实例化（Scoped/Transient）** 的（例如 FastAPI 默认的 `Depends(MyClass)`），向 `self.user` 赋值是安全的，因为不同请求拥有不同的对象引用。扫描器若按单例（Singleton）逻辑推断则会误报。

#### 4. 证实标准

若以下条件**全部满足**，应将该漏洞判定为 **True Positive (证实)**：
1. **异步环境确认**：执行环境为异步（涉及 `async def`, `await`, 或明确的 ASGI 框架）。
2. **共享状态写入**：JWT 解析后的用户信息被写入了共享作用域。具体表现为：
   - 使用了 `global` 关键字修改模块级变量。
   - 向 `threading.local()` 的实例写入数据（在 `async` 协程中，多个协程跑在同一个线程，会导致隔离失效）。
   - 向生命周期为全局单例（Singleton）的实例属性（`self.xxx`）写入数据。
3. **状态被异步挂起打断**：在状态写入和后续状态读取之间，存在 `await` 操作（如 I/O 操作、数据库查询等），这导致当前协程交出控制权，为其他并发请求覆盖该共享状态提供了窗口。
4. **无校验读取**：下游业务逻辑直接从上述共享作用域中读取身份标识执行敏感操作。

#### 5. 证伪标准

若满足以下**任意一条**，应将该漏洞判定为 **False Positive (证伪)**：
1. **协程安全变量**：身份信息的存储变量被明确定义为 `contextvars.ContextVar`，且读写操作均通过其内置的 `.set()` 和 `.get()` 方法完成。
2. **请求绑定存储**：数据被挂载到框架明确隔离的请求上下文容器中（如 `request.state`, `request.scope`, 或 Quart 的 `g` 变量）。
3. **局部作用域与显式传参**：身份信息仅存在于函数的局部变量中，并作为参数在函数调用栈中显式向下层传递，没有任何脱离函数作用域的驻留。
4. **非单例的实例属性**：虽然存在 `self.user = parsed_user` 的操作，但通过溯源实例化过程，确认该对象的作用域（Scope）是每次请求独立创建的，并非全局复用的单例对象。