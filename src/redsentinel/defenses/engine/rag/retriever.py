import os
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from rank_bm25 import BM25Okapi

from redsentinel.defenses.engine.config import *


class _TextOnlyHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self.parts.append(text)


class _BM25Retriever:
    def __init__(self, documents) -> None:
        self.documents = list(documents)
        self.k = 4
        self._index = BM25Okapi(
            [document.page_content.split() for document in self.documents]
        )

    @classmethod
    def from_documents(cls, documents):
        return cls(documents)

    def invoke(self, query: str):
        query_tokens = query.split()
        scores = self._index.get_scores(query_tokens)
        query_terms = set(query_tokens)
        ranked = sorted(
            enumerate(scores),
            key=lambda item: (
                -item[1],
                -len(query_terms & set(self.documents[item[0]].page_content.split())),
                item[0],
            ),
        )
        return [self.documents[index] for index, _score in ranked[: self.k]]

# ===================== 重排序模型配置 =====================
RERANK_MODEL_PATH = "BAAI/bge-reranker-base"
ENABLE_RERANK = True

rerank_model = None
_rerank_load_attempted = False


def _get_rerank_model():
    """Lazy-load reranker so importing the RAG module stays lightweight."""
    global ENABLE_RERANK, rerank_model, _rerank_load_attempted
    if not ENABLE_RERANK:
        return None
    if rerank_model is not None:
        return rerank_model
    if _rerank_load_attempted:
        return None
    _rerank_load_attempted = True
    try:
        from sentence_transformers import CrossEncoder
        rerank_model = CrossEncoder(RERANK_MODEL_PATH, local_files_only=True)
        print("[OK] 离线重排序模型加载成功")
        return rerank_model
    except Exception as e:
        print(f"[WARN] 重排序模型加载失败：{str(e)}")
        ENABLE_RERANK = False
        return None

# ===================== OCR 扫描件支持 =====================
_ocr_reader = None
OCR_MIN_CHARS = 30  # Pages with fewer than this many CJK chars are considered scanned


def _get_ocr_reader():
    """Lazy-init EasyOCR reader for Chinese text."""
    global _ocr_reader
    if _ocr_reader is None:
        import easyocr
        _ocr_reader = easyocr.Reader(['ch_sim', 'en'], gpu=True, verbose=False)
        print("[OK] EasyOCR 扫描件识别引擎已加载")
    return _ocr_reader


def _needs_ocr(text: str, threshold: int = None) -> bool:
    """Check if extracted text is too sparse — likely a scanned page."""
    t = threshold if threshold is not None else OCR_MIN_CHARS
    import re
    cjk = len(re.findall(r'[一-鿿]', text))
    return cjk < t


def _ocr_page(pdf_path: str, page_num: int) -> str:
    """Render a single PDF page to image and run OCR. Returns extracted text."""
    import fitz  # pymupdf
    import numpy as np
    doc = fitz.open(pdf_path)
    try:
        page = doc[page_num]
        pix = page.get_pixmap(dpi=200)
        # Convert PyMuPDF pixmap to numpy array (RGB) for EasyOCR
        img_array = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
            pix.height, pix.width, pix.n
        )
        if pix.n == 4:
            img_array = img_array[:, :, :3]  # drop alpha
        reader = _get_ocr_reader()
        results = reader.readtext(img_array, detail=0)
        return "\n".join(results)
    finally:
        doc.close()


def ocr_enrich_documents(docs: list, pdf_path: str, verbose: bool = True) -> list:
    """Scan all loaded documents. Replace page_content with OCR text
    for pages that have insufficient extractable text."""
    # Group docs by page number
    pages_replaced = 0
    for doc in docs:
        page_num = doc.metadata.get("page", 0)
        if _needs_ocr(doc.page_content):
            try:
                ocr_text = _ocr_page(pdf_path, page_num)
                if ocr_text and len(ocr_text) > len(doc.page_content):
                    doc.page_content = ocr_text
                    pages_replaced += 1
            except Exception as e:
                if verbose:
                    print(f"  [WARN] OCR failed for page {page_num + 1}: {e}")
    if verbose and pages_replaced > 0:
        print(f"[OK] OCR 已识别 {pages_replaced}/{len(set(d.metadata.get('page', 0) for d in docs))} 个扫描页")
    return docs


# ===================== 上下文智能过滤 =====================
# 文档结构预分析缓存
_doc_guide_cache = {}

def generate_document_guide(retriever_dict) -> str:
    """Extract document taxonomy/classification info via LLM (cached, one-time cost)."""
    docs = retriever_dict.get("docs", [])
    if not docs:
        return ""

    doc_key = str(id(docs))
    if doc_key in _doc_guide_cache:
        return _doc_guide_cache[doc_key]

    sample = "\n".join([d.page_content for d in docs[:3]])[:1500]
    if not sample.strip():
        return ""

    try:
        from langchain_openai import ChatOpenAI
        from redsentinel.defenses.engine.config import LLM_MODEL, LLM_API_BASE, LLM_API_KEY
        llm = ChatOpenAI(
            model=LLM_MODEL, temperature=0.0, max_tokens=200,
            openai_api_base=LLM_API_BASE, openai_api_key=LLM_API_KEY
        )
        prompt = f"""分析文档片段，提取结构化信息。只输出结果，不解释。

1. 文档类型与主题
2. 如果有分类/类别/类型字段，列出所有可选值
3. 如果有状态字段，列出所有可选值
4. 关键命名实体

文档：
{sample}"""
        guide = llm.invoke(prompt).content.strip()
        _doc_guide_cache[doc_key] = guide
        return guide
    except Exception:
        return ""


def build_context_window(ranked_docs: list, max_chars: int = 2048) -> str:
    """Build context string from ranked docs within char budget. Top docs get priority."""
    context_parts = []
    source_docs = []
    used = 0
    for idx, doc in enumerate(ranked_docs):
        page_num = doc.metadata["page"]
        file_name = doc.metadata["file_name"]
        source_id = idx + 1
        source_docs.append({
            "id": source_id,
            "file_name": file_name,
            "page": page_num,
            "content": doc.page_content[:100] + "..."
        })
        block = f"[{source_id}] 【{file_name} 第{page_num}页】\n{doc.page_content}\n"
        if used + len(block) <= max_chars:
            context_parts.append(block)
            used += len(block)
        else:
            remaining = max_chars - used
            if remaining > 100:
                context_parts.append(block[:remaining] + "...")
            break

    # Build text enrichment: extract potential category values
    full_text = "".join([d.page_content for d in ranked_docs])
    categories_hint = _extract_categories_hint(full_text)

    context = "\n".join(context_parts)
    if categories_hint:
        context = f"【文档关键信息预提取】\n{categories_hint}\n\n【文档原文片段】\n{context}"

    return context, source_docs


def _extract_categories_hint(text: str) -> str:
    """Reconstruct table structure from garbled PDF text extraction.
    Identifies potential category values at line endings and groups related data."""
    import re
    from collections import Counter, defaultdict

    lines = [l.strip() for l in text.split('\n') if l.strip()]
    if len(lines) < 4:
        return ""

    # ---- Step 1: Extract potential category values from line endings ----
    # Category values often appear as 2-4 char CJK strings at end of longer lines
    ending_counter = Counter()
    ending_examples = defaultdict(list)
    for line in lines:
        if 10 < len(line) < 120:
            for end_len in [4, 3, 2]:
                ending = line[-end_len:]
                if re.match(r'^[一-鿿]{2,4}$', ending):
                    ending_counter[ending] += 1
                    desc = line[:-end_len].rstrip('，,、。.')
                    ending_examples[ending].append(desc)
                    break

    # ---- Step 2: Identify the most likely category values ----
    # A true category value appears multiple times at line endings
    likely_categories = [(cat, cnt) for cat, cnt in ending_counter.most_common(20) if cnt >= 2]

    # ---- Step 3: Build structured summary ----
    hints = []
    if likely_categories:
        cat_names = [c for c, _ in likely_categories[:5]]
        hints.append(f"【从文档中提取到的可能分类/类型值】: {', '.join(cat_names)}")

        # For each category, show a few example rows
        for cat, cnt in likely_categories[:4]:
            examples = ending_examples[cat][:3]
            if examples:
                hints.append(f"\n类型「{cat}」(出现{cnt}次) 的条目示例:")
                for ex in examples:
                    short = ex[:60] + ("..." if len(ex) > 60 else "")
                    hints.append(f"  - {short}")

    # ---- Step 4: Also extract short repeated lines (status values, headers) ----
    short_lines = Counter([l for l in lines if 2 <= len(l) <= 6 and re.match(r'^[一-鿿]+$', l)])
    repeated_short = [(w, c) for w, c in short_lines.most_common(10) if c >= 2]
    if repeated_short:
        short_vals = [w for w, _ in repeated_short[:6]]
        if short_vals:
            hints.append(f"\n【文档中重复出现的短词（可能是状态值/列名）】: {', '.join(short_vals)}")

    return '\n'.join(hints) if hints else ""

def _detect_format(path: str) -> str:
    """Detect document format from file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return "pdf"
    if ext in (".html", ".htm"):
        return "html"
    if ext in (".eml", ".mht"):
        return "email"
    if ext in (".md", ".markdown"):
        return "markdown"
    return "text"


def _load_document(path: str, fmt: str):
    """Load document based on detected format."""
    if fmt == "pdf":
        import fitz

        pdf = fitz.open(path)
        try:
            return [
                Document(
                    page_content=page.get_text(),
                    metadata={"source": path, "page": page.number},
                )
                for page in pdf
            ]
        finally:
            pdf.close()
    if fmt == "html":
        parser = _TextOnlyHTMLParser()
        parser.feed(Path(path).read_text(encoding="utf-8", errors="replace"))
        return [
            Document(
                page_content="\n".join(parser.parts),
                metadata={"source": path, "page": 0},
            )
        ]
    if fmt == "markdown":
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return [
            Document(
                page_content=re.sub(r"<[^>]+>", "", content),
                metadata={"source": path, "page": 0},
            )
        ]
    if fmt == "email":
        return _load_email_document(path)
    return [
        Document(
            page_content=Path(path).read_text(encoding="utf-8", errors="replace"),
            metadata={"source": path, "page": 0},
        )
    ]


def _load_email_document(path: str):
    """Load .eml email with MIME parsing.

    Extracts headers (Subject, From, To, X-Priority, X-Urgency) and text body.
    Splits multipart boundaries into separate document pages.
    """
    import email as _email
    from langchain_core.documents import Document

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    msg = _email.message_from_string(raw)
    docs = []

    # Extract headers as metadata
    meta = {
        "subject": str(_email.header.decode_header(msg.get("Subject", ""))[0][0]
                       if _email.header.decode_header(msg.get("Subject", "")) else ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "x_priority": msg.get("X-Priority", ""),
        "x_urgency": msg.get("X-Urgency", ""),
        "file_name": os.path.basename(path),
    }

    content_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    text = payload.decode("utf-8", errors="replace")
                if ct == "text/plain" or ct == "text/html":
                    content_parts.append((ct, text))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                text = payload.decode("utf-8", errors="replace")
            content_parts.append((msg.get_content_type(), text))

    # Assemble document: headers + all body parts
    full_text = f"Subject: {meta['subject']}\nFrom: {meta['from']}\nTo: {meta['to']}\n"
    if meta["x_priority"]:
        full_text += f"X-Priority: {meta['x_priority']}\n"
    if meta["x_urgency"]:
        full_text += f"X-Urgency: {meta['x_urgency']}\n"
    full_text += "\n"
    for ct, text in content_parts:
        # Strip HTML tags for clean text extraction
        import re as _re
        clean = _re.sub(r"<[^>]+>", "", text)
        full_text += clean + "\n"

    doc = Document(page_content=full_text, metadata=meta)
    docs.append(doc)
    return docs


def init_rag_retriever(pdf_path: str = None, force_reindex: bool = False,
                       session_id: str = None, persist: bool = True,
                       chunk_size: int = None, chunk_overlap: int = None,
                       enable_rerank: bool = None, vec_top_k: int = None,
                       rerank_top_n: int = None, enable_ocr: bool = True):
    """Initialize RAG retriever with Chroma vector store (persistent).

    Args:
        pdf_path: Path to the PDF file.
        force_reindex: If True, delete existing index and rebuild.
        session_id: Optional session ID for multi-tenant isolation (Streamlit).
        persist: If True, persist to disk. If False, use in-memory (session uploads).
        chunk_size: Override config CHUNK_SIZE. None = use config default.
        chunk_overlap: Override config CHUNK_OVERLAP. None = use config default.
        enable_rerank: Override ENABLE_RERANK. None = use module default.
        vec_top_k: Override vector/bm25 top_k. None = use config TOP_K.
        rerank_top_n: Override RERANK_TOP_N. None = use config default.
        enable_ocr: If True, auto-detect scanned pages and run OCR.
    """
    _chunk_size = chunk_size if chunk_size is not None else CHUNK_SIZE
    _chunk_overlap = chunk_overlap if chunk_overlap is not None else CHUNK_OVERLAP
    _enable_rerank = enable_rerank if enable_rerank is not None else ENABLE_RERANK
    _vec_top_k = vec_top_k if vec_top_k is not None else TOP_K
    _rerank_top_n = rerank_top_n if rerank_top_n is not None else RERANK_TOP_N
    if pdf_path is None:
        from redsentinel.defenses.engine.config import DEFAULT_TEST_PDF
        pdf_path = DEFAULT_TEST_PDF
    # Multi-format document loading.
    doc_fmt = _detect_format(pdf_path)
    docs = _load_document(pdf_path, doc_fmt)

    for doc in docs:
        doc.metadata["file_name"] = os.path.basename(pdf_path)

    # OCR: auto-detect scanned pages and extract text from images
    if enable_ocr:
        docs = ocr_enrich_documents(docs, pdf_path)

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=_chunk_size,
        chunk_overlap=_chunk_overlap,
        separators=["\n\n\n", "\n\n", "\n", "。", "！", "？", "；", "，", " ", ""],
        is_separator_regex=False
    )
    splits = splitter.split_documents(docs)

    # Security: scan chunks at ingestion time (L1 rule-based, no API calls)
    try:
        from redsentinel.defenses.engine.security.ingest.doc_scanner import sanitize_splits
        splits, scan_reports = sanitize_splits(splits)
        flagged = [r for r in scan_reports if r.get("is_suspicious")]
        if flagged:
            print(f"[SEC] 文档扫描: {len(splits)} chunks入库, {len(flagged)} 标记可疑(未入库)")
    except ImportError:
        pass

    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

    # Collection name: PDF filename + chunk params + optional session suffix
    # Encoding chunk_size/overlap ensures different experiment configs use separate indexes
    pdf_basename = os.path.splitext(os.path.basename(pdf_path))[0]
    parts = [pdf_basename, f"cs{_chunk_size}", f"co{_chunk_overlap}"]
    collection_name = "_".join(parts)
    if session_id:
        collection_name = f"{collection_name}_{session_id}"

    if persist:
        persist_dir = str(CHROMA_PERSIST_DIR)
        os.makedirs(persist_dir, exist_ok=True)

        # Force reindex: delete existing collection if present
        if force_reindex:
            existing_path = os.path.join(persist_dir, collection_name)
            if os.path.exists(existing_path):
                shutil.rmtree(existing_path)
                print(f"[*] 已清除旧索引: {collection_name}")

        # Try loading existing collection first (avoid re-embedding)
        try:
            chroma_db = Chroma(
                collection_name=collection_name,
                embedding_function=embeddings,
                persist_directory=persist_dir
            )
            if chroma_db._collection.count() > 0:
                print(f"[OK] Chroma 从磁盘加载已有索引: {collection_name} ({chroma_db._collection.count()} chunks)")
            else:
                # Empty collection, populate it
                chroma_db = Chroma.from_documents(
                    documents=splits, embedding=embeddings,
                    collection_name=collection_name, persist_directory=persist_dir
                )
                print(f"[OK] Chroma 持久化索引已创建: {collection_name} ({len(splits)} chunks)")
        except Exception:
            # Collection doesn't exist yet, create it
            chroma_db = Chroma.from_documents(
                documents=splits, embedding=embeddings,
                collection_name=collection_name, persist_directory=persist_dir
            )
            print(f"[OK] Chroma 持久化索引已创建: {collection_name} ({len(splits)} chunks)")
    else:
        # Ephemeral in-memory mode (for session-level temp uploads)
        chroma_db = Chroma.from_documents(
            documents=splits,
            embedding=embeddings,
            collection_name=collection_name
        )

    vec_retriever = chroma_db.as_retriever(
        search_type="mmr",
        search_kwargs={"k": _vec_top_k, "fetch_k": max(_vec_top_k * 3, 10), "lambda_mult": 0.7}
    )

    bm25_retriever = _BM25Retriever.from_documents(splits)
    bm25_retriever.k = _vec_top_k

    return {
        "bm25": bm25_retriever,
        "vector": vec_retriever,
        "docs": splits,
        "chroma_db": chroma_db,
        "collection_name": collection_name,
        "enable_rerank": _enable_rerank,
        "rerank_top_n": _rerank_top_n
    }

def rerank_docs(query: str, docs, top_n: int = RERANK_TOP_N):
    model = _get_rerank_model()
    if not model or not docs:
        return docs[:top_n]

    pairs = [[query, doc.page_content] for doc in docs]
    scores = model.predict(pairs)
    sorted_docs = sorted(zip(docs, scores), key=lambda x: x[1], reverse=True)
    return [doc for doc, score in sorted_docs[:top_n]]

def rag_query(retriever_dict, query: str,
              enable_rerank: bool = None, rerank_top_n: int = None):
    _enable_rerank = enable_rerank if enable_rerank is not None else retriever_dict.get("enable_rerank", ENABLE_RERANK)
    _rerank_top_n = rerank_top_n if rerank_top_n is not None else retriever_dict.get("rerank_top_n", RERANK_TOP_N)
    strategy = retriever_dict.get("strategy", None)
    bm25_retriever = retriever_dict["bm25"]
    vec_retriever = retriever_dict["vector"]

    if strategy == "vector_only":
        vec_docs = vec_retriever.invoke(query)
        all_docs = list({d.page_content: d for d in vec_docs}.values())
    elif strategy == "bm25_only":
        bm25_docs = bm25_retriever.invoke(query)
        all_docs = list({d.page_content: d for d in bm25_docs}.values())
    else:
        bm25_docs = bm25_retriever.invoke(query)
        vec_docs = vec_retriever.invoke(query)

        # RRF (Reciprocal Rank Fusion) merge -- k=60 is the standard parameter
        def _rrf_merge(vec_docs, bm25_docs, k=60):
            scores = {}
            doc_map = {}
            for rank, doc in enumerate(vec_docs):
                doc_id = f"{doc.metadata.get('page', 0)}_{doc.page_content[:50]}"
                scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
                doc_map[doc_id] = doc
            for rank, doc in enumerate(bm25_docs):
                doc_id = f"{doc.metadata.get('page', 0)}_{doc.page_content[:50]}"
                scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
                doc_map[doc_id] = doc
            return [doc_map[did] for did, _ in sorted(scores.items(), key=lambda x: x[1], reverse=True)]

        all_docs = _rrf_merge(vec_docs, bm25_docs)

    if not all_docs:
        return "未找到相关内容", []

    # Honor enable_rerank from retriever (set per-experiment); skip rerank if strategy is single-source
    if strategy in ("vector_only", "bm25_only") or not _enable_rerank:
        ranked_docs = all_docs[:_rerank_top_n]
    else:
        ranked_docs = rerank_docs(query, all_docs, _rerank_top_n)

    # Security: scan retrieved chunks before building context (L1+L2 cascading)
    try:
        from redsentinel.defenses.engine.security.ingest.doc_scanner import scan_retrieved_chunks
        chunk_texts = [d.page_content for d in ranked_docs]
        scans = scan_retrieved_chunks(chunk_texts)
        ranked_docs = [d for i, d in enumerate(ranked_docs)
                       if not scans[i].get("should_filter")]
    except ImportError:
        pass

    context, source_docs = build_context_window(ranked_docs)
    return context, source_docs
