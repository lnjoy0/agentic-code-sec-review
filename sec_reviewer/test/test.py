import sys
from pathlib import Path

# 将项目根目录动态添加到 sys.path 中，便于运行该脚本文件
project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from tools.knowledge_retriever import VulnKnowledgeBase

vkb = VulnKnowledgeBase()
tool = vkb.create_expert_tool('Injection_Expert')
tool.invoke("Path_Traversal")