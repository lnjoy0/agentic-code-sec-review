import sys
from pathlib import Path

# 将项目根目录动态添加到 sys.path 中，便于运行该脚本文件
project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from tools.knowledge_retriever import VulnKnowledgeBase

def main():
    """该脚本用于将知识库文档预构建为向量数据库，并持久化保存"""
    VulnKnowledgeBase.create_vector_db()

if __name__ == "__main__":
    main()