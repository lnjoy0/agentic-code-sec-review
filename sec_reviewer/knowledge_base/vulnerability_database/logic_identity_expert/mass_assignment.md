---
cwe_id: ["CWE-915"]
name: "Mass_Assignment"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
应用程序在接收外部输入时，未通过白名单严格限制可更新的属性，直接将包含不可信参数的完整数据字典（或反序列化对象）批量解包或绑定到内部数据模型/业务对象上，导致攻击者能够越权篡改诸如权限（role）、状态（status）或余额（balance）等敏感特权字段。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
此类漏洞通常发生在处理资源创建（POST）和资源更新（PUT/PATCH）的 API 路由或表单提交入口中（如 FastAPI 路由、Django 视图、Flask 接口）。当前的请求身份标识（如从 JWT 解析出的 `request.user`）本身可能是合法的，且认证与横向越权（IDOR）校验可能也是正常的，但**请求载荷（Payload）上下文**处于失控状态。攻击者在原本合法的 JSON 或表单数据中，静默插入未授权的额外键值对（例如 `{"username": "test", "is_admin": true}`），系统在解析输入时原样接收了整个 Payload 字典。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
漏洞爆发的核心动作在于**批量属性赋值或数据库持久化操作**。在 Python 环境中，典型的危险目标模式包括：
*   **ORM 批量操作**：直接使用字典解包更新 Django/SQLAlchemy 模型，例如 `User.objects.filter(id=uid).update(**request.data)` 或 `User.objects.create(**request.json)`。
*   **内置字典更新**：使用原生 Python 方法批量覆盖对象属性，如 `user.__dict__.update(request.json)` 或通过循环 `setattr(user, key, value)` 且不加限制。
*   **反序列化框架误用**：在反序列化时（如 Marshmallow、Pydantic），将外部数据实例化为模型后，直接将其完整映射到数据库实体，而目标实体包含了额外的特权字段。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
代码中缺失了针对外部输入数据的**字段级白名单约束（Allowlist Filtering）**：
*   **缺失序列化器约束**：在 Django REST Framework (DRF) 中，未使用 Serializer 的 `fields = ('name', 'age')` 限制，而是错误使用了 `fields = '__all__'`，或者直接绕过 Serializer 使用 `request.data`。
*   **缺失 Pydantic 模型隔离**：在 FastAPI 中，外部输入直接使用了包含敏感字段的数据库模型（或继承了全量字段的基类模型）作为 Type Hint，而不是使用专用的、仅包含允许修改字段的进站模型（如 `UserCreate` / `UserUpdate` 对应的 Schema）。
*   **缺失字典过滤**：在执行 `**kwargs` 批量赋值前，代码未对提取自 `request` 的字典执行按需取值，也未剔除（pop）敏感字段。

#### 3. 典型误报样例

1. **使用了安全的强类型反序列化模型**：扫描器匹配到了 `User.objects.create(**user_data)`，但向上溯源发现 `user_data` 是通过 `user_data = schema.model_dump(exclude_unset=True)` 提取的，且该 `schema` (如 Pydantic BaseModel) 内部严格定义了仅包含普通字段，不存在提权字段。
2. **目标模型本身无特权字段**：扫描器发现了一处对 `Comment` 或 `Tag` 表的批量赋值 `Comment.objects.create(**request.POST)`，但审查该模型（Model）的定义发现，其所有字段（如 `content`, `author_id`, `created_at`）本身就是允许用户侧自由指定的，没有利用价值。
3. **显式的黑名单过滤**：在执行解包前，代码中存在针对性的过滤逻辑，例如 `data = request.json; data.pop("is_superuser", None); data.pop("role", None); user.update(**data)`（虽然白名单是最佳实践，但完整的黑名单也能有效缓解漏洞，被视为误报）。

#### 4. 证实标准

若以下条件**全部满足**，则证实为漏洞（True Positive）：
1. **输入可控**：数据字典的来源直接或间接是用户输入（如 `request.data`, `request.json`, `request.args`）。
2. **批量执行**：数据通过 `**` 解包、`setattr` 遍历、或 `update()` 方法被批量绑定到了内部对象或 ORM 模型上。
3. **敏感字段存在**：被绑定的目标模型（Model）类定义中，明确包含不应由普通请求篡改的特权字段（如 `is_admin`, `is_staff`, `role`, `balance`, `vip_level`, `status` 等）。
4. **验证缺失**：从数据获取到执行批量赋值的整个数据流中，不存在白名单结构（如定义了限制字段的 Serializer / Pydantic Schema）且不存在有效的敏感字段剔除逻辑。

#### 5. 证伪标准

若满足以下**任意一条**，则应判定为误报（False Positive）：
1. **白名单隔离（DTO模式）**：输入数据在解包前，已被传入严格限制了字段的验证器（如 DRF 的 Serializer 配置了具体的 `fields` 元组，或 FastAPI 强制映射为了不包含特权字段的 Pydantic 模型）。解包所用的字典来源于验证器清洗后的数据（如 `serializer.validated_data`）。
2. **逐个字段显式赋值**：代码看似处理了整个请求，但在最终赋值给模型时是逐个点对点映射的，例如 `User(name=data.get('name'), age=data.get('age'))`，未使用的额外输入会被自然丢弃。
3. **低价值目标实体**：被更新的 ORM 模型极其简单，其所有字段按业务逻辑都允许用户任意修改，没有任何越权操作的杠杆点（如单纯的文本草稿箱表）。
4. **操作属于高特权上下文**：该段代码逻辑位于一个严格的高权限后台管理接口（如 Superadmin Panel），调用者本身已经被确认为最高权限，此时修改任何字段都在其合法权限范围内。