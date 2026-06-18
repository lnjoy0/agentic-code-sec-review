---
cwe_id: ["CWE-840"]
name: "Business_State_Machine_Bypass"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
攻击者通过构造非预期的请求顺序、跳过必要前置步骤或直接篡改请求中的状态参数，打破了系统设计的业务状态转换约束，使得应用在未满足前置条件的情况下，非法执行了后续的关键业务操作（如未支付直接发货）。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
此类漏洞通常发生在涉及多步流转的业务 API 路由中（如 `/cart/checkout` -> `/order/pay` -> `/order/deliver` -> `/order/complete`）。
在身份上下文方面，请求往往能正确通过 `request.user` 或 JWT 验证其合法用户身份，但在**状态上下文**的获取上存在混淆或伪造风险：
- **状态参数客户端化**：当前所处步骤或状态由前端控制并作为参数传入（如 `POST /api/step` 携带 `{"step": 3, "status": "paid"}`），服务端直接信任该上下文。
- **上下文隔离失效**：多步操作依赖服务端 Session 或 Redis 缓存，但未校验“当前请求所属的流程实例 ID（如 OrderID）”与 Session 中记录的“已完成鉴权实例 ID”是否严格一致，导致张冠李戴。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
敏感动作通常表现为对系统核心资产的**状态跃迁执行**或**价值转移**：
- **ORM 状态字段更新**：直接通过 SQLAlchemy 或 Django ORM 修改状态标识（如 `order.status = 'SHIPPED'`，`payment.is_cleared = True` 并执行 `.save()` 或 `.commit()`）。
- **触发后续业务链**：调用发货服务、执行资金扣款、发放优惠券、生成激活码等（如调用 `send_virtual_goods(order.id)`）。
- **持久化不可逆数据**：将本应在最终审核阶段落库的数据，提前写入主表或区块链。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
代码中缺失了对于对象**当前生命周期状态**的强制防守：
- **缺少前置状态断言**：在执行后置操作（如发货）前，ORM 查询未将前置状态作为过滤条件（如仅 `Order.objects.get(id=order_id, user=request.user)`，缺失了 `.filter(status='PAID')`），也未在代码逻辑中进行 `if order.status != 'PAID'` 的校验。
- **状态跃迁无白名单控制**：使用了动态赋值或批量赋值（Mass Assignment），允许用户直接传入目标状态字段，且服务端未限制该状态只允许由系统内部回调或特定前置状态单向变更。
- **校验与执行脱节（TOCTOU）**：虽然校验了状态，但由于多步操作间缺乏事务级的一致性或正确的并发控制，导致状态校验在并发场景下被绕过。

#### 3. 典型误报样例

1. **统一网关或中间件已拦截 (Middleware/Decorator Validation)**：
   扫描器发现 API 路由函数体内没有状态校验逻辑，但实际上使用了 FastAPI 的 `Depends(verify_order_paid)`，或 Django 的 `@require_order_status('PAID')` 装饰器，状态校验在进入核心控制器前已经完成。
2. **底层状态机库自动防守 (FSM Library Enforcement)**：
   项目中使用了类似 `transitions` 或 `django-fsm` 的状态机库。代码中直接调用了 `order.ship()`，扫描器认为缺少前置校验，但实际上底层状态机 `@transition(source='PAID', target='SHIPPED')` 已经硬性规定了跃迁路径，不满足会抛出异常。
3. **后台管理越权操作 (Admin/Ops APIs)**：
   被扫描的代码属于内部 Ops 接口或 Admin 路由（如 `/admin/order/force_ship`）。这类接口的业务逻辑本就是为了应对异常情况进行强制状态覆盖，不受常规用户状态机的限制，不应视作状态机绕过（需通过鉴权审计维度检查）。
4. **业务上合法的跳跃 (Legitimate Business Skip)**：
   某些特定类型的对象在业务上确实无需经历所有状态。例如，虚拟商品订单（Virtual Goods）在付款后直接跃迁至“已完成（COMPLETED）”，无需经历“发货（SHIPPED）”状态，此为符合业务预期的逻辑分叉。

#### 4. 证实标准

若以下条件**全部满足**，则证实为漏洞（True Positive）：
1. 目标函数或方法执行了明确的后置敏感操作（如发货、发奖、结账）。
2. 该接口对公网暴露，或可被低权限/普通用户访问。
3. 在溯源该请求的处理链路时（包括依赖注入、装饰器、中间件以及函数体本身），**未能找到**针对核心对象当前业务状态（`status`, `step`, `is_paid` 等）的强校验逻辑。
4. 状态判断依赖于不可信输入（用户可控参数），或无论对象处于什么状态，该代码逻辑都会强制将其修改为目标状态。

#### 5. 证伪标准

若满足以下**任意一条**，则应判定为误报（False Positive）：
1. **存在显式阻断**：在执行关键操作前，代码显式查询了可信存储（DB/Redis）获取当前状态，并在状态不符时抛出异常、返回错误或直接 `return`。
2. **ORM 过滤机制**：虽然没有 `if` 判断，但数据库查询直接将状态作为了限制条件，如 `db.query(Order).filter_by(id=req.id, status='PAID').one()`，状态不符时会因查询不到对象而自然阻断。
3. **存在框架级拦截**：状态机校验逻辑被抽象在全局/路由级别的中间件、拦截器、FastAPI `Depends` 或装饰器中，且该拦截器正确作用于当前 API。
4. **受控的底层封装**：对象的状态修改方法被封装在模型层，且利用了状态机库（如 `django-fsm`）或在 Model 的 `save()`/setter 方法中内置了固定的流转限制规则。