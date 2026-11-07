"""Qwen tokenizer access with a development-only estimate fallback."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import Config


class TokenCounter:
    """Count Qwen tokens locally when the setup script has installed its tokenizer."""

    CHARS_PER_TOKEN = 4

    def __init__(self, tokenizer_path: Path | None = None) -> None:
        self.tokenizer_path = tokenizer_path or Config.TOKENIZER_PATH
        self._tokenizer: Any = None
        self._load_attempted = False

    @property
    def mode(self) -> str:
        self._load_tokenizer()
        return "qwen3" if self._tokenizer is not None else "character-estimate"

    def count_tokens(self, text: str) -> int:
        """Return the Qwen3 token count, or a coarse estimate before setup."""
        if not text:
            return 0
        self._load_tokenizer()
        if self._tokenizer is not None:
            return len(self._tokenizer.encode(text).ids)
        return max(1, len(text) // self.CHARS_PER_TOKEN)

    def truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Return a prefix whose measured token count does not exceed the limit."""
        if max_tokens <= 0:
            return ""
        if self.count_tokens(text) <= max_tokens:
            return text

        low, high = 0, len(text)
        while low < high:
            middle = (low + high + 1) // 2
            if self.count_tokens(text[:middle]) <= max_tokens:
                low = middle
            else:
                high = middle - 1
        return text[:low]

    def _load_tokenizer(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        if not self.tokenizer_path.is_file():
            return

        try:
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise RuntimeError(
                "The Qwen tokenizer file exists but the 'tokenizers' package is "
                "missing. Install dependencies with: pip install -r requirements.txt"
            ) from exc

        self._tokenizer = Tokenizer.from_file(str(self.tokenizer_path))


token_counter = TokenCounter()
