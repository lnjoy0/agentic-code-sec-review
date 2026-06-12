---
cwe_id: ['CWE-470']
name: 'Dynamic_Reflection_Abuse'
domain: ["Logic_Identity_Expert", "General_Expert"]
---

#### 1. 漏洞机制

Python 动态特性与反射滥用：攻击者通过控制未加清洗的外部输入，利用 Python 的 `getattr()`、`setattr()`、`globals()`、`locals()` 或 `__import__()` 等动态反射和元编程机制，越权访问、修改内部属性或意外调用危险的敏感/系统方法。

#### 2. 典型漏洞代码样例

```python
# 典型漏洞代码样例：基于全局变量或对象属性的动态路由
import sys
import os

class WebActionController:
    def get_user_info(self, uid):
        return f"User info for {uid}"
    
    def get_status(self):
        return "System OK"

def dynamic_route_handler(request):
    action_name = request.GET.get("action")
    controller = WebActionController()
    
    # 漏洞点：直接将外部输入用于 getattr，且随后进行函数调用
    if hasattr(controller, action_name):
        action_func = getattr(controller, action_name)
        return action_func()
    
    # 另一个常见的漏洞点：利用 globals() 动态调用
    # func = globals().get(action_name)
    # if func: return func()
```

##### 1. 业务意图与高风险特性 (Business Intent & High-Risk Features)
业务为了提高代码复用性、减少冗长的 `if-elif-else` 分支，实现灵活的 API 路由、动态插件加载或工厂模式（Business Intent），使用了 Python 强大的动态反射内置函数（如 `getattr`、`globals()` 或基于 `sys.modules` 的模块查找）。这种设计允许在运行时根据字符串变量动态决定要解析和调用的对象属性或函数（High-Risk Features）。

##### 2. 威胁面与非预期执行 (Threat Surface & Unsafe Execution)
攻击者通过传入精心构造的恶意属性名称（Threat Surface），打破业务仅调用 `get_user_info` 等普通方法的预期。例如，在 `getattr` 场景中，攻击者可传入 `__class__`、`__init__` 等 Python 魔法方法来访问对象元数据，或者如果作用域/对象设计不当，甚至可以访问到 `os.system` 等导入的模块方法；在修改场景（`setattr`）中，攻击者可能篡改对象的内部状态、越权修改鉴权标志（如动态设置 `is_admin=True`）；最终导致信息泄露、访问控制绕过或远程代码执行（RCE）。

##### 3. 缓解措施与资源/边界限制 (Mitigations & Boundary Limits)
代码在将外部输入传递给动态执行上下文之前，缺失了显性的防御边界：
1. 缺失静态的白名单（Allowlist）校验限制合法属性集；
2. 缺失对字符串前缀的强制约束（例如禁止下划线 `_` 开头的属性访问以保护私有和魔法方法）；
3. 或者本应使用安全的“字典映射（Dict Mapping）”模式来替代无限制的内置动态求值机制。

#### 3. 典型误报样例

```python
# 误报样例 1：严格的白名单校验
def safe_route_with_allowlist(request):
    action = request.GET.get("action")
    ALLOWED_ACTIONS = {"ping", "status", "health"}
    
    # 虽然使用了外部输入和 getattr，但在白名单保护下是安全的
    if action in ALLOWED_ACTIONS:
        controller = WebActionController()
        func = getattr(controller, action)
        return func()

# 误报样例 2：物理隔离的高安全前缀机制
def safe_route_with_prefix(request):
    user_action = request.GET.get("action")
    # 强制拼接前缀，攻击者无论如何输入，都无法拼接出 __class__ 这种魔法属性
    # 例如输入 __class__ 会变成 action___class__
    safe_action_name = f"action_{user_action}" 
    
    controller = WebActionController()
    if hasattr(controller, safe_action_name):
        func = getattr(controller, safe_action_name)
        return func()
```

1. **哈希字典安全映射 (Dict Dispatching):** 代码并未使用底层的反射函数，而是预先定义了字典映射（如 `ACTION_MAP = {"ping": do_ping, "info": do_info}`），通过 `ACTION_MAP.get(user_input)` 获取执行句柄。即便用户输入异常，也只会返回 `None`。
2. **强制前缀/后缀隔离 (Forced Prefixing):** 用户的输入在进入 `getattr` 前被强制拼接了固定字符串（如 `method_name = f"action_{user_input}"`，随后调用 `getattr(obj, method_name)`）。由于目标对象内部不存在以 `action_` 开头的高危系统方法或魔法属性（如不可能存在 `action___class__`），从而切断了越权访问路径。
3. **隔离的无害上下文 (Isolated Dummy Context):** `getattr` 操作的目标对象是一个纯粹的数据类（DataClass）或极其受限的命名空间，该对象没有任何敏感的方法、属性，且所在模块没有导入任何危险库，攻击者即使任意读取也无法引发实质性危害。
4. **内部硬编码/枚举控制 (Internal Enum Control):** 传入 `getattr` 的变量虽然是动态获取的，但其来源是系统内部数据库中安全的枚举值或硬编码列表，并非由外部 API 或不受信实体直接传入。

#### 4. 证实标准

如果**同时满足**以下条件，应研判为**真实漏洞（True Positive）**：
1. 数据源可控：变量来源于未经过滤的外部输入（如 HTTP 请求参数、反序列化数据、未校验的数据库读取等）。
2. 触发敏感汇聚点：该变量被直接作为参数传入 `getattr()`、`setattr()`、`globals()`、`locals()` 或作为模块加载参数传入 `__import__()` / `importlib.import_module()`。
3. 缺失边界校验：到达上述 Sink（汇聚点）之前的执行流中，不存在针对该变量的白名单检查。
4. 存在攻击利用面：被反射的目标对象（Target Object）内部或上下文中存在可供利用的高危属性、方法或已加载的敏感模块；且反射获取的属性如果被后续代码直接执行（如 `getattr(...)()`），危害极大增加。

#### 5. 证伪标准

如果满足以下**任一条件**，应研判为**误报 (False Positive)**：
1. 白名单阻断：在执行反射调用前，输入已被限制在一个预先定义好的硬编码集合（Allowlist/Enum）内。
2. 安全前缀阻断：反射调用的属性名被代码强制加上了特定的前缀或后缀（如 `getattr(obj, "cmd_" + input)`），这在物理上杜绝了攻击者访问 Python 魔法方法（`__` 开头）及其他非预期方法的可能。
3. 安全的字典映射机制：代码并没有使用高危内置函数，而是通过静态字典（如 `action_map = {"a": funcA}`）进行安全匹配。即使扫描器因语义相似误报，也应证伪。
4. 数据源无关：传入 `getattr` 或 `globals()` 的变量完全在本地或服务端内部写死（Hardcoded），不存在被外部数据污染（Taint）的路径。