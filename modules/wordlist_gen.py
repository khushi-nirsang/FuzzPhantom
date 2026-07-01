"""
FuzzPhantom — Smart Wordlist Generator
Generates a domain-specific wordlist by analyzing page content.
Two modes:
  - Lightweight: frequency-based word extraction
  - NLP: TF-IDF scoring with nltk stopword filtering (requires nltk + sklearn)
"""

from __future__ import annotations

import asyncio
import re
import string
from collections import Counter
from pathlib import Path

from bs4 import BeautifulSoup

from core.context import ScanContext
from core.session import FuzzSession
from core.logger import get_logger, console

logger = get_logger(__name__)

# ── Common English stopwords (lightweight fallback) ──────────────────────────
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "is", "are", "was", "were",
    "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "shall", "can",
    "of", "in", "on", "at", "to", "for", "with", "by", "from", "up",
    "about", "into", "over", "after", "this", "that", "these", "those",
    "it", "its", "we", "our", "they", "their", "you", "your", "he",
    "she", "his", "her", "not", "no", "so", "as", "if", "then", "than",
    "when", "where", "who", "which", "how", "what", "all", "each",
    "more", "some", "such", "new", "also", "any", "just", "now",
    "com", "www", "http", "https", "html", "class", "div", "span",
}

_TOKEN_RE = re.compile(r"[a-z][a-z0-9_\-]{2,30}", re.IGNORECASE)


def _extract_text_tokens(html: str) -> list[str]:
    """Strip HTML and extract meaningful word tokens."""
    soup = BeautifulSoup(html, "lxml")

    # Remove noise
    for tag in soup(["script", "style", "noscript", "meta", "head"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    tokens = _TOKEN_RE.findall(text)
    return [t.lower() for t in tokens if t.lower() not in _STOPWORDS and len(t) > 2]


def _tfidf_wordlist(
    corpus: list[list[str]], top_n: int = 200
) -> list[str]:
    """
    Compute TF-IDF scores and return top_n terms.
    Uses sklearn if available, otherwise falls back to frequency.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        import numpy as np

        docs = [" ".join(doc) for doc in corpus]
        vectorizer = TfidfVectorizer(
            max_features=500,
            min_df=1,
            stop_words="english",
        )
        matrix = vectorizer.fit_transform(docs)
        scores = np.asarray(matrix.sum(axis=0)).flatten()
        features = vectorizer.get_feature_names_out()
        top_indices = scores.argsort()[::-1][:top_n]
        return [features[i] for i in top_indices]
    except ImportError:
        logger.warning("sklearn not available. Falling back to frequency-based wordlist.")
        counter: Counter = Counter()
        for doc in corpus:
            counter.update(doc)
        return [word for word, _ in counter.most_common(top_n)]


async def generate_smart_wordlist(ctx: ScanContext, top_n: int = 200) -> list[str]:
    """
    Crawl target pages and generate a domain-specific wordlist.
    Stores results in ctx.smart_wordlist_terms and saves to reports dir.
    """
    console.rule("[bold cyan]Smart Wordlist Generator[/bold cyan]")

    urls_to_analyze = (ctx.crawled_urls or [])[:50]  # Cap at 50 pages
    if not urls_to_analyze:
        start = (
            f"https://{ctx.target_domain}"
            if not ctx.target_domain.startswith("http")
            else ctx.target_domain
        )
        urls_to_analyze = [start]

    corpus: list[list[str]] = []

    async with FuzzSession(ctx) as session:
        for url in urls_to_analyze:
            try:
                resp = await session.get(url)
                if resp is None:
                    continue
                async with resp:
                    if resp.status >= 400:
                        continue
                    html = await resp.text(errors="replace")
                    tokens = _extract_text_tokens(html)
                    if tokens:
                        corpus.append(tokens)
                        logger.info(
                            f"  Analyzed: [cyan]{url}[/cyan] → {len(tokens)} tokens"
                        )
            except Exception as exc:
                logger.debug(f"Wordlist gen error {url}: {exc}")

    if not corpus:
        logger.warning("No content to analyze for wordlist generation.")
        return []

    wordlist = _tfidf_wordlist(corpus, top_n=top_n)
    ctx.smart_wordlist_terms = wordlist

    # Save to output directory
    out_dir = Path(ctx.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "smart_wordlist.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"# FuzzPhantom Smart Wordlist — {ctx.target_domain}\n")
        f.write(f"# Terms: {len(wordlist)}\n\n")
        f.write("\n".join(wordlist))

    logger.info(
        f"[bold green]Smart wordlist generated.[/bold green] "
        f"[bold]{len(wordlist)}[/bold] terms → [cyan]{out_path}[/cyan]"
    )
    return wordlist
