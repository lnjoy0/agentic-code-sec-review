---
cwe_id: ["CWE-639"]
name: "IDOR-Horizontal_Privilege_Escalation"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
应用程序在处理用户请求时，未充分校验被访问目标对象的归属权，导致攻击者可以通过修改请求中的资源标识符（如ID、订单号等），非法访问、修改或删除属于其他同级别用户的敏感数据或执行未授权操作。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
*   **入口特征**：通常出现在 RESTful API 路由路径（如 `@app.get("/api/users/{user_id}/orders")`）、URL 查询参数（如 `?order_id=123`）或请求体 JSON payload 中接收资源标识符的端点。
*   **身份上下文**：系统已通过认证机制获取了当前操作者的身份（如 Django 的 `request.user`、Flask 的 `current_user`、FastAPI 的 `Depends(get_current_user)`），但业务逻辑**仅提取外部传入的目标资源ID**，而没有将该 ID 与当前身份上下文进行强绑定。存在严重的上下文割裂风险。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
*   **敏感数据读取**：执行 ORM 查询操作以获取隐私数据（如 `User.objects.get(id=user_id)` 或 SQLAlchemy 的 `session.query(Order).get(order_id)`），并将包含敏感字段的序列化对象返回给客户端。
*   **状态机跃迁与敏感修改**：对目标对象执行更新（UPDATE）或删除（DELETE）操作，如取消他人的订单（`order.status = 'CANCELLED'`）、修改他人账户的收货地址、甚至是重置他人密码。
*   **关联操作**：向属于他人的容器对象中添加资源（例如，将商品加入他人的购物车ID）。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
*   **缺失横向归属权校验（最核心特征）**：ORM 查询或更新操作未带上属主过滤条件。
    *   **易受攻击的写法**：直接根据传入的 ID 查询（如 `Order.objects.get(id=target_id)`）。
    *   **安全的写法**：结合当前用户查询（如 `Order.objects.get(id=target_id, owner=request.user)` 或 `request.user.orders.get(id=target_id)`）。
*   **缺失对象级鉴权控制 (Object-Level Permission Missing)**：在获取到对象实例后，未执行显式的属主比对逻辑（如缺失 `if obj.user_id != request.user.id: raise PermissionDenied`），也未使用框架提供的对象级权限装饰器/中间件（如 Django 的 `has_object_permission`）。
*   **标识符过于规律（辅助特征）**：系统使用了自增的整数型 ID 而非不可预测的 UUID，使得攻击者可以轻易地通过遍历 ID 发起批量越权攻击（注：使用 UUID 不能修复 IDOR，但能显著增加利用难度）。

#### 3. 典型误报样例

1.  **公开资源的正常访问**：请求获取了指定 ID 的文章、公开的商品详情或公开的用户主页资料，该资源的业务属性本就允许任意用户查看，无需校验属主。
2.  **管理后台的垂直操作**：API 路由虽然没有校验 `owner=request.user`，但在路由入口处已有 `@require_admin`、`@has_role('manager')` 等装饰器。由于当前用户身份是管理员，本来就拥有跨用户操作的权限，此时不属于水平越权。
3.  **内部已经隐式校验了归属**：开发者没有在 ORM 查询时显式写 `user_id=...`，但在调用的 Service 层函数或序列化器（Serializer）中，通过上下文验证了权限；或者 ID 并非直接来自用户输入，而是从服务器端 Session 或加密不可篡改的 Token（如 JWT Claims）中解析出来的。
4.  **操作对象全局唯一且不依赖用户归属**：例如全局配置项查询、字典表查询等，无用户归属属性。

#### 4. 证实标准

当满足以下**全部条件**时，可判定为真实漏洞：
1.  **污染源确认**：资源标识符（如 `id`、`user_id`、`order_no`）明确来自于用户可控的 HTTP 输入（Path, Query, Body, Header）。
2.  **执行目标确认**：后端在处理该标识符时，执行了 ORM 数据库查询、文件读取或状态更新等敏感操作，且该对象包含非公开的用户专有数据或状态。
3.  **权限校验缺失确认**：确认以下三点均不存在：
    1. ORM 查询条件中没有带入当前用户身份（如缺少 `owner=request.user`）。
    2. 函数体内没有显式的对象属主比对逻辑。
    3. 路由入口或视图类上没有挂载用于对象级鉴权的装饰器（如 `@has_object_permission`）或权限依赖注入。
4. **非公开属性确认**：根据变量命名、表名（如 `PrivateMessage`, `UserWallet`）或业务逻辑，确认该被操作的对象属于用户私有资产，而非全局公开或内部共享资源。

#### 5. 证伪标准

只要满足以下**任意一项**，即可判定为误报：
1.  **查询级属主约束**：ORM/SQL 语句在查询时，除了目标 ID，已经将当前上下文用户（如 `user_id`, `tenant_id`, `org_id`）作为过滤条件（例如：`User.orders.get(id=...`, `.filter(id=req_id, user_id=current_user.id)` 或使用关联模型 `current_user.items.get(...)`）。
2.  **显式代码级拦截**：提取对象后，代码中存在类似于 `if obj.owner != request.user: return 403` 或 `assert_ownership(obj)` 的逻辑判断，或者调用了自定义的 `check_object_permission(user, obj)` 函数。
3.  **框架级与装饰器鉴权**：接口使用了专门的对象级权限控制机制，例如：
    1. 路由存在 `@require_admin`, `@roles_accepted('manager')` 等高权限约束。
    2. 使用了诸如 `IsOwnerOrReadOnly`、`check_object_permission` 等策略类/中间件。
    3. 依赖注入中包含了校验逻辑（如 `FastAPI` 的 `Depends(verify_ownership)`）。
4.  **间接属主归属**：目标资源虽然没有直接关联 `user_id`，但关联了 `group_id` 或 `tenant_id`，且系统在更上层已经校验了当前用户对该 Group/Tenant 的访问权限（RBAC/ABAC 模式）。
5.  **不可控凭据安全提取**：虽然存在 `user_id` 或 `target_id` 变量，但该变量并非来自请求体/URL，而是从受信任的 Server-Side Session、Redis 缓存或经过签名验签的 JWT Token Payload 中直接提取。
6.  **对象公开性**：该资源接口在设计上本就是公开可读的（如博客文章详情页 `GET /article/{id}`、公开商品库查询）。