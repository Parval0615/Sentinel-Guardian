from pathlib import Path

import pytest
from langchain_core.documents import Document

from redsentinel.defenses.engine.rag.retriever import (
    _BM25Retriever,
    _load_document,
)


pytestmark = pytest.mark.fast


@pytest.mark.parametrize(
    ("suffix", "content", "expected"),
    [
        (".txt", "plain security policy", "plain security policy"),
        (".md", "# Policy\n<strong>trusted</strong>", "# Policy\ntrusted"),
        (".html", "<main><h1>Policy</h1><p>trusted content</p></main>", "Policy\ntrusted content"),
    ],
)
def test_document_loader_uses_maintained_direct_parsers(
    tmp_path: Path,
    suffix: str,
    content: str,
    expected: str,
) -> None:
    path = tmp_path / f"document{suffix}"
    path.write_text(content, encoding="utf-8")

    documents = _load_document(str(path), {".md": "markdown", ".html": "html"}.get(suffix, "text"))

    assert [document.page_content for document in documents] == [expected]
    assert documents[0].metadata == {"source": str(path), "page": 0}


def test_bm25_retriever_returns_the_most_relevant_documents() -> None:
    documents = [
        Document(page_content="public product policy", metadata={"page": 0}),
        Document(page_content="restricted payment token", metadata={"page": 1}),
    ]
    retriever = _BM25Retriever.from_documents(documents)
    retriever.k = 1

    result = retriever.invoke("payment token")

    assert result == [documents[1]]
