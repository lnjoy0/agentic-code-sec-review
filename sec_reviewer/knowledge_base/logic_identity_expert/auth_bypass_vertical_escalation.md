---
cwe_id: ["CWE-269", "CWE-285"]
name: "Auth_Bypass_Vertical_Escalation"
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制
系统在处理高权限敏感业务请求时，未能正确验证当前请求主体的角色或权限等级，导致低权限用户（或未认证用户）能够成功调用并执行管理员或特权用户才能执行的操作。

#### 2. 漏洞逻辑与上下文特征 (Vulnerability Logic & Context Patterns)

##### 1. 业务入口与身份上下文 (Business Endpoint & Identity Context)
*   **高危入口特征**：通常存在于后台管理接口（如带有 `/admin/`, `/system/`, `/manage/` 前缀的路由）、系统配置更新接口、或者用户角色管理接口。在 Python 框架中体现为 FastAPI 的 `@app.post("/admin/roles")`、Django 的 `urls.py` 路由映射或 Flask 的 `@app.route`。
*   **身份获取与混淆风险**：上下文通常已经通过了基础的身份认证（如 JWT 解析出了 `user_id` 或 `request.user.is_authenticated == True`），证明“你是谁”，但并未在此基础上验证“你能做什么”。攻击者利用普通用户的有效 Token 请求高权限接口，若代码仅依赖“Token 是否有效”而未校验“Token 中的 Role 字段”，即发生垂直越权。

##### 2. 关键业务操作与目标 (Critical Business Operation & Target)
*   **系统级/全局数据变更**：执行了影响整个系统的 ORM 数据库操作。例如：`SystemSettings.objects.update(...)`，或更改了其他用户的状态 `User.query.filter_by(id=target_id).update({"is_active": False})`。
*   **特权对象操作**：进行了只有管理员才能执行的增删改查。例如：封禁用户、分配角色、查看全局财务报表、下发系统通知。
*   **特权字段的批量赋值（Mass Assignment）**：在用户信息更新等接口中，将前端传入的 JSON 数据直接反序列化并保存到 ORM 模型中（如 `user.__dict__.update(request.json); user.save()`），导致原本普通的业务接口被利用来修改 `is_superuser`、`role`、`permissions` 等特权字段。

##### 3. 缺失的校验与逻辑约束 (Missing Validations & Logic Constraints)
*   **缺失的路由级门禁**：在 FastAPI 中缺失权限依赖注入（如缺少 `Depends(verify_admin_role)`）；在 Django 中缺失视图装饰器（如 `@user_passes_test`、`@permission_required`）或未继承相应的鉴权 Mixin（如 `PermissionRequiredMixin`）；在 Flask 中缺失 `@roles_accepted` 等约束。
*   **缺失的业务级逻辑锁**：在函数体内部执行敏感数据库操作前，未包含类似 `if not request.user.is_admin: raise HTTPException(403)` 的断言逻辑。
*   **缺失的参数白名单限制（批量赋值风险）**：在接收反序列化数据（如 `request.json()`）并在 ORM 中进行解包赋值（`**data`）时，未对高权限字段（如 `is_superuser`, `role`, `permissions`）进行硬编码过滤或使用 Pydantic/Django ModelForm 的白名单机制，导致低权限用户通过附加特权字段实现“隐式”垂直越权。

#### 3. 典型误报样例

1.  **全局路由/网关层鉴权拦截**：代码本身（如具体的 FastAPI router 函数体内）没有任何权限校验逻辑，但该接口挂载的父级 Router `APIRouter(dependencies=[Depends(require_admin)])` 已经全局注入了权限校验，或外层的 API 网关（如 APISIX, Kong）通过拦截 `/admin/*` 路由并校验 JWT Claims 完成了鉴权。
2.  **基类隐式鉴权**：在 Django CBV（Class-Based Views）中，目标 View 继承了自定义的 `AdminBaseView`，该基类重写了 `dispatch` 方法或使用了 `SuperUserMixin` 进行了严格的权限验证。扫描器仅分析当前文件/当前类，导致误报。
3.  **内网/异步任务特权操作**：被扫描的代码属于 Celery Task（如 `@celery.task`）、Django Management Command（`BaseCommand`）或 RPC 内部调用服务。这些端点根本不通过外网 HTTP 直接暴露，其调用方已被确认为受信的内部服务，因此无需在此处做用户态的权限校验。
4.  **模型层强约束过滤**：虽然视图函数接收了完整的用户 payload 并在 ORM 中更新了数据，但入口使用了严格的 Pydantic 模型（如 FastAPI 的 schema）或 Django Form。这些 Schema 中明确未包含或禁用了 `is_admin` 等高权字段的反序列化，从而在数据验证层就已经阻断了特权字段注入。

#### 4. 证实标准

当满足以下**全部条件**时，可判定为真实漏洞：
1.  **端点暴露性**：该函数或类明确绑定了对外的 HTTP 路由（如包含 router 装饰器），且业务逻辑涉及高权限敏感操作。
2.  **身份获取仅限基础认证**：代码上下文仅从请求头或 Session 中获取了用户身份（验证了登录状态），但未进一步检查 `role`, `is_admin`, `is_staff`, `permissions` 等权限属性。
3.  **权限门禁彻底缺失**：在当前函数、类装饰器、父类继承链、以及框架路由注册层（如 FastAPI include_router 时的 dependencies），均未发现鉴权相关的依赖引用。
4.  **危险的对象操作**：请求参数中的数据（哪怕是隐式包含的）能够直接抵达 ORM 层修改敏感状态，且途中没有任何黑白名单对参数的 keys 进行清洗。

#### 5. 证伪标准

只要满足以下**任意一项**，即可判定为误报：
1.  **依赖注入与装饰器防护**：上下文中存在明确的权限校验装饰器或依赖项（如 FastAPI 的 `Depends(check_admin)`，Django 的 `@permission_required` 等）。
2.  **基于代码的硬性覆盖**：即使攻击者传入了特权参数，业务逻辑在执行持久化操作前，使用当前上下文强制重写了该字段（例如：`payload['role'] = 'USER'` 或 `Model.objects.create(..., role=Role.NORMAL)`）。
3.  **框架级的白名单校验**：输入数据经过了 Pydantic Schema 或 Serializer 的处理，且该 Schema 的定义中明确剔除了高危字段（如 Pydantic BaseModel 未定义 `role` 属性并设置了 `extra = "forbid"`）。
4.  **环境隔离证明**：代码结构及文件路径（如 `tests/`, `scripts/`, `management/commands/`）表明该逻辑不在 Web 服务的 Request-Response 生命周期内执行，不存在 HTTP 越权攻击面。