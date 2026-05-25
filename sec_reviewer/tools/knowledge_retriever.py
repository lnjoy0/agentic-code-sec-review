import logging
import frontmatter
import shutil
import json
from typing import Annotated, List
from pathlib import Path
from langchain_core.tools import StructuredTool
from langchain_core.documents import Document
from langchain_core.tools.base import InjectedToolArg
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain_community.retrievers import BM25Retriever
from langchain_classic.retrievers import EnsembleRetriever
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from core.config import EmbeddingConfig


logger = logging.getLogger(__name__)


KNOWLEDGE_ROOT_PATH = Path(__file__).parent.parent.resolve() / 'knowledge_base' # 知识库根目录
PERSIST_DIRECTORY = KNOWLEDGE_ROOT_PATH / 'persist_db' # 持久化保存数据库的目录
MAPPING_PATH = PERSIST_DIRECTORY / "doc_path_mapping.json" # 文档路径映射表地址


class StrictBM25Retriever(BM25Retriever):
    """带有零分截断机制的 BM25 检索器"""
    
    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        # 按照 BM25 算法对 query 分词
        tokenized_query = self.preprocess_func(query)
        
        # 获取所有文档的 BM25 绝对得分
        scores = self.vectorizer.get_scores(tokenized_query)
        
        # 剔除所有得分为 0 (没有任何关键词命中) 的文档
        valid_docs_with_scores = [
            (self.docs[i], score) for i, score in enumerate(scores) if score > 0
        ]
        
        # 按分数从高到低排序
        valid_docs_with_scores.sort(key=lambda x: x[1], reverse=True)
        
        # 截取 Top K 并剥离分数，返回纯 Document 列表
        top_docs = [doc for doc, score in valid_docs_with_scores[:self.k]]
        
        # 改造这里：截取 Top K 的同时，将 BM25 分数注入到 metadata 中
        top_docs = []
        for doc, score in valid_docs_with_scores[:self.k]:
            doc.metadata["bm25_score"] = round(score, 4) # 保留4位小数
            top_docs.append(doc)

        return top_docs

class VulnKnowledgeBase:
    """安全知识库"""
    
    def __init__(self):
        self.vectorstore = self._init_vectorstore()

        if MAPPING_PATH.exists():
            with open(MAPPING_PATH, "r", encoding="utf-8") as f:
                self.doc_path_mapping = json.load(f)
        else:
            self.doc_path_mapping = {}

        # 缓存每个专家的 BM25 Retriever，避免重复构建
        self._bm25_retrievers = {}

    @staticmethod
    def _init_vectorstore():
        embed_config = EmbeddingConfig()
        vllm_embeddings = OpenAIEmbeddings(
            model=embed_config.model_name, 
            base_url=embed_config.base_url, 
            api_key=embed_config.api_key
        )
        return Chroma(
            persist_directory=str(PERSIST_DIRECTORY), 
            embedding_function=vllm_embeddings
        )

    def _get_or_create_bm25_retriever(self, expert_name: str, top_k) -> BM25Retriever:
        """加载或创建特定专家的 BM25 检索器"""
        if expert_name in self._bm25_retrievers:
            return self._bm25_retrievers[expert_name]

        logger.info(f"正在为 {expert_name} 构建专属 BM25 索引...")
        
        # 从 Chroma 底层集合中，提取属于该专家的所有文档
        results = self.vectorstore._collection.get(
            where={"domain": {"$contains": expert_name}},
            include=["documents", "metadatas"]
        )
        
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])
        
        if not documents:
            logger.warning(f"未找到属于 {expert_name} 的文档，无法构建 BM25。")
            return None

        # 将底层数据还原为 LangChain 的 Document 对象
        lc_docs = [Document(page_content=doc, metadata=meta) for doc, meta in zip(documents, metadatas)]
        
        # 初始化 BM25 Retriever
        bm25_retriever = StrictBM25Retriever.from_documents(lc_docs)
        bm25_retriever.k = top_k
        
        self._bm25_retrievers[expert_name] = bm25_retriever
        return bm25_retriever

    def _core_hybrid_search(
        self, 
        query: str, 
        expert_name: str,
        viewed_docs: Annotated[list, InjectedToolArg] = None, # 已经看过的文档，用于文档去重
        new_docs: Annotated[list, InjectedToolArg] = None, # 新文档列表的引用，用于传递新看过的文档名称
        top_k: int = 3
    ) -> str:
        """混合检索 (BM25 + Vector + RRF) """
        try:
            # ================= [新增代码：旁路打印向量得分] =================
            raw_vector_results = self.vectorstore.similarity_search_with_relevance_scores(
                query=query,
                k=top_k,
                filter={"domain": {"$contains": expert_name}}
            )
            print(f"\n🔍 [调试信息] 查询: '{query}'")
            print("--- 向量检索 (Vector) 得分 ---")
            for doc, score in raw_vector_results:
                print(f"得分: {score:.4f} | 文档: {doc.metadata.get('name')}")
            # ==========================================================

            # 初始化特定专家的向量检索器
            vector_retriever = self.vectorstore.as_retriever(
                search_type="similarity_score_threshold",
                search_kwargs={
                    "k": top_k,
                    "filter": {"domain": {"$contains": expert_name}}, # 过滤出属于该专家领域的文档
                    "score_threshold": 0.5 # 防止并不相关的文档被检索出来占用上下文空间
                }
            )
            
            # 获取 BM25 检索器
            bm25_retriever = self._get_or_create_bm25_retriever(expert_name, top_k)
            
            # 构建混合检索器
            if bm25_retriever:
                # 打印一下 BM25 原生召回的结果及分数
                print("--- 关键词检索 (BM25) 得分 ---")
                bm25_docs = bm25_retriever.invoke(query)
                for doc in bm25_docs:
                    print(f"得分: {doc.metadata.get('bm25_score')} | 文档: {doc.metadata.get('name')}")

                ensemble_retriever = EnsembleRetriever(
                    retrievers=[bm25_retriever, vector_retriever],
                    weights=[0.5, 0.5] # 权重
                )
                chunks = ensemble_retriever.invoke(query)
            else:
                chunks = vector_retriever.invoke(query)

            # 取经过 RRF 算法融合后的前两名
            chunk = chunks[2]
            if not chunks:
                return f"📄 在知识库中未找到与 `{query}` 相关的基准规则。"

            viewed_docs = viewed_docs or []
            retrieved_docs = []

            for chunk in chunks:
                doc_name = chunk.metadata.get("name", "")

                # 仅考虑没看过的文档
                if doc_name and doc_name not in viewed_docs:
                    rel_path = self.doc_path_mapping.get(doc_name, "")
                    if rel_path:
                        abs_path = KNOWLEDGE_ROOT_PATH / rel_path

                        # 从绝对路径读取文档内容
                        try:
                            with open(abs_path, 'r', encoding='utf-8') as f:
                                raw_content = f.read()
                                pure_content = frontmatter.loads(raw_content).content
                                retrieved_docs.append({
                                    "name": doc_name,
                                    "content": pure_content
                                })
                        except FileNotFoundError:
                            logger.warning(f"⚠️ 警告: 找不到物理文件 {abs_path}，已跳过该文档")
                            continue
                
                    # 添加检索到的文档名，防止重复文档占用上下文
                    viewed_docs.append(doc_name)
                    if new_docs is not None:
                        new_docs.append(doc_name) # 用于将新文档名传递给子图状态

            if not retrieved_docs:
                return f"📄 检索到了与 `{query}` 相关的文档，但它们都已包含在您当前的上下文中。"

            # 拼接排版输出
            output_lines = [
                f"### 📚 知识检索结果 (Hybrid Search)",
                f"> **检索词**: `{query}`",
                "---",
                ""  # 加一个空行，防止大模型将后续内容与分隔符粘连
            ]

            for doc in retrieved_docs:
                # 拼接 XML 格式 
                doc_content = doc["content"].strip() 
                doc_block = (
                    f'<doc title="{doc["name"]}">\n'
                    f'{doc_content}\n'
                    f'</doc>'
                )
                output_lines.append(doc_block)
                output_lines.append("")

            return "\n".join(output_lines)

        except Exception as e:
            logger.error(f"知识库检索异常: {e}")
            return f"❌ 检索失败: `{str(e)}`"

    def create_expert_tool(self, expert_name: str) -> StructuredTool:
        """生成目标专家领域的知识库混合检索工具"""
        def knowledge_retrieval(
                query: str, 
                viewed_docs: Annotated[list, InjectedToolArg] = None,
                new_docs: Annotated[list, InjectedToolArg] = None
            ) -> str:
            """
            检索目标漏洞的知识文档，获取漏洞的成因分析、框架特征、误报样例以及权威的误报（FP）/真实漏洞（TP）研判基准。

            【何时使用】：
            1. [初始查询] 接收到扫描器报告后，研判开始前，【必须】先调用此工具获取该漏洞类型的相关知识。
            2. [类型纠正] 研判过程中，若发现代码的实际逻辑与扫描器报告的漏洞类型存在偏差（例如扫描器报 XSS，但实际代码上下文为 SSTI），需再次调用该工具以获取正确漏洞类型的知识文档。

            【Query 编写技巧】：
            底层采用 BM25(关键词匹配) + Vector(语义匹配) 混合检索。
            建议先对自己想要查询的目标知识做自我解释或回答，然后将这个解释或回答作为 query 内容。

            【文档结构预期】：
            召回的文档标准结构包含5部分：
            1.漏洞机制 | 2.漏洞代码/配置特征 | 3.典型误报样例 | 4.证实标准(TP) | 5.证伪标准(FP)

            Args:
                query (str): 查询语句。系统会自动限定在你所属的专家领域内检索，并自动过滤你已经看过的文档（无需担心重复）。
            
            Returns:
                str: 排版好的 Markdown 知识库文档，包裹在 <doc title="..."> 标签中。
            """
            return self._core_hybrid_search(
                query=query, 
                expert_name=expert_name,
                viewed_docs=viewed_docs,
                new_docs=new_docs
            )

        return StructuredTool.from_function(
            func=knowledge_retrieval, 
            name=f"knowledge_retrieval"
        )

    @classmethod
    def create_vector_db(cls):
        """使用知识库文档构建向量数据库"""
        if PERSIST_DIRECTORY.exists():
            print(f"🧹 正在清理旧的向量数据库: {PERSIST_DIRECTORY}")
            shutil.rmtree(PERSIST_DIRECTORY)
            
        print("🚀 开始初始化向量数据库构建...")
        vectorstore = cls._init_vectorstore()

        headers_to_split_on = [
            ("####", "Section"),
            ("#####", "SubSection")
        ]
        markdown_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=headers_to_split_on)

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=200,
            chunk_overlap=50,
            length_function=len,
            separators=["\n\n", "\n*   ", "\n", " ", ""]
        )

        all_chunks = []
        doc_path_mapping = {}

        # 遍历所有 Markdown 文件
        for md_file in KNOWLEDGE_ROOT_PATH.rglob('*.md'):
            with open(md_file, 'r', encoding='utf-8') as f:
                md_content = f.read()

            # 剥离 YAML 与 正文
            parsed_file = frontmatter.loads(md_content)
            yaml_metadata = parsed_file.metadata
            pure_markdown_content = parsed_file.content

            # 存储该文档的相对路径，用于父子文档检索 (Small-to-Big)
            rel_path = md_file.relative_to(KNOWLEDGE_ROOT_PATH)
            doc_name = yaml_metadata.get('name', md_file.stem)
            doc_path_mapping[doc_name] = str(rel_path)

            # 按 Markdown 标题结构切分
            header_chunks = markdown_splitter.split_text(pure_markdown_content)

            # 执行二级切分，防止最小标题下的内容仍然过长
            final_chunks = text_splitter.split_documents(header_chunks)

            for chunk in final_chunks:                
                # 提取 MarkdownHeaderTextSplitter 生成的标题层级 metadata
                section = chunk.metadata.get("Section", "")
                sub_section = chunk.metadata.get("SubSection", "")
                
                # 构建上下文前缀，将文档名称和标题名都注入到分块内容中（上下文检索）
                context_prefix = f"【文档所属漏洞类型】: {doc_name}\n"
                if section:
                    context_prefix += f"【主模块】: {section}\n"
                if sub_section:
                    context_prefix += f"【子模块】: {sub_section}\n"
                
                # 将前缀物理注入到 page_content 中
                chunk.page_content = f"{context_prefix}【内容】:\n{chunk.page_content}"
                
                # 更新元数据
                chunk.metadata.update(yaml_metadata)
                chunk.metadata['name'] = doc_name
                chunk.metadata['domain'] = yaml_metadata.get('domain', ["General_Expert"])            
            
            all_chunks.extend(final_chunks)
            
        if not all_chunks:
            print("❌ 未提取到任何有效的文档切片。")
            return

        # 持久化存储路径映射表
        with open(MAPPING_PATH, "w", encoding="utf-8") as f:
            json.dump(doc_path_mapping, f) 
        
        print(f"✅ 成功将 {len(doc_path_mapping)} 个文档路径映射持久化至: {MAPPING_PATH}")

        # 将文档切片向量化，并入库
        vectorstore.add_documents(all_chunks)

        print(f"✅ 成功将 {len(all_chunks)} 个知识切片写入 Chroma 数据库，并持久化至: {PERSIST_DIRECTORY}")
