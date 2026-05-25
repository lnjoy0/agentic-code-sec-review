import sys
from pathlib import Path

# 将项目根目录动态添加到 sys.path 中，便于运行该脚本文件
project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from tools.knowledge_retriever import VulnKnowledgeBase

"""
vllm serve /hy-tmp \
    --task embed \
    --served-model-name Qwen3-Embedding-8B \
    --trust-remote-code \
    --port 8080 \
    --max-model-len 8192 \
    --gpu-memory-utilization 0.9
"""

kb = VulnKnowledgeBase()

# print(kb._core_hybrid_search(
#     query="stack overflow in C++", 
#     expert_name="General_Expert"
# ))
"""
🔍 [调试信息] 查询: 'stack overflow in C++'
--- 向量检索 (Vector) 得分 ---
得分: 0.3041 | 文档: XML_External_Entity_Injection
得分: 0.2838 | 文档: Dockerfile_Security_Baseline_Violations
得分: 0.2729 | 文档: Deprecated_Ciphers
--- 关键词检索 (BM25) 得分 ---
得分: 2.9889 | 文档: Command_Injection
得分: 2.8977 | 文档: Path_Traversal
得分: 2.6923 | 文档: Weak_Randomness
No relevant docs were retrieved using the relevance score threshold 0.5
"""

print(kb._core_hybrid_search(
    query="AES ECB mode", 
    expert_name="General_Expert"
))
"""
🔍 [调试信息] 查询: 'Server-Side Template Injection 漏洞机制'
--- 向量检索 (Vector) 得分 ---
得分: 0.3150 | 文档: SQL_Injection
得分: 0.2757 | 文档: SQL_Injection
得分: 0.2644 | 文档: Deserialization_of_Untrusted_Data
--- 关键词检索 (BM25) 得分 ---
得分: 6.146 | 文档: Server-Side_Template_Injection
No relevant docs were retrieved using the relevance score threshold 0.5
"""