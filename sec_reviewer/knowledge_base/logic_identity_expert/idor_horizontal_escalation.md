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
3.  **权限校验缺失确认**：在数据操作的上游到下游完整执行链路中，**未发现**当前用户身份（`request.user` 等）与目标资源所有者之间的比对逻辑，且查询条件中没有将当前用户作为过滤参数。
4.  **环境前提约束**：该接口允许普通身份的认证用户访问，且业务场景不支持跨用户共享或查看。

#### 5. 证伪标准

只要满足以下**任意一项**，即可判定为误报：
1.  **查询条件已包含属主约束**：ORM 语句在查询时，除了传入的 ID，还显式带入了当前身份上下文（例如：`.filter(id=req_id, user_id=current_user.id)` 或使用关联模型 `current_user.items.get(...)`）。
2.  **存在显式的鉴权屏障**：代码中存在诸如 `if target_obj.owner != request.user:` 的硬编码判断并抛出异常，或者调用了自定义的 `check_object_permission(user, obj)` 函数。
3.  **受控的管理员端点**：该入口明确使用了依赖注入或装饰器限制了只有 Admin/Superuser 角色才能访问。
4.  **资源公开性**：根据业务逻辑上下文或对象命名（如 `PublicArticle`, `SharedBoard`），被访问的资源被设计为公开或允许当前工作组/租户内全员共享的。
5.  **不可控标识符**：该 ID 参数虽然在后端逻辑中使用，但其实际来源并非外部传入，而是由后端从受信任的会话（Session）中安全取出的。