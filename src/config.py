"""
Configuration management using environment variables.
Provides type-safe access to all application settings.
"""
import os
from pathlib import Path


class Config:
    """Application configuration loaded from environment variables."""

    # Ollama settings
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3:8b")
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "180"))

    # Token budget settings (must not exceed model context limit)
    MAX_CONTEXT_TOKENS: int = int(os.getenv("MAX_CONTEXT_TOKENS", "2048"))
    MAX_CHUNK_TOKENS: int = int(os.getenv("MAX_CHUNK_TOKENS", "1200"))
    MAX_OUTPUT_TOKENS: int = int(os.getenv("MAX_OUTPUT_TOKENS", "320"))
    SAFETY_MARGIN_TOKENS: int = int(os.getenv("SAFETY_MARGIN_TOKENS", "96"))
    SYSTEM_PROMPT_TOKENS: int = 220
    TASK_INSTRUCTION_TOKENS: int = 80
    CONTEXT_SUMMARY_TOKENS: int = 100
    PROMPT_OVERHEAD_TOKENS: int = (
        SYSTEM_PROMPT_TOKENS +
        TASK_INSTRUCTION_TOKENS +
        CONTEXT_SUMMARY_TOKENS
    )

    # Application settings
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
    UPLOAD_DIR: Path = Path(os.getenv("UPLOAD_DIR", "./uploads"))
    DATABASE_PATH: Path = Path(os.getenv("DATABASE_PATH", "./data/analyzer.db"))
    TOKENIZER_PATH: Path = Path(
        os.getenv("TOKENIZER_PATH", "./data/qwen3-tokenizer.json")
    )

    # Server settings
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    @classmethod
    def validate(cls) -> None:
        """Validate configuration consistency."""
        # Ensure token budget doesn't exceed context limit
        total_reserved = (
            cls.SYSTEM_PROMPT_TOKENS +
            cls.TASK_INSTRUCTION_TOKENS +
            cls.CONTEXT_SUMMARY_TOKENS +
            cls.MAX_CHUNK_TOKENS +
            cls.MAX_OUTPUT_TOKENS +
            cls.SAFETY_MARGIN_TOKENS
        )

        if total_reserved > cls.MAX_CONTEXT_TOKENS:
            raise ValueError(
                f"Token budget ({total_reserved}) exceeds context limit "
                f"({cls.MAX_CONTEXT_TOKENS}). "
                f"Breakdown: prompt={cls.PROMPT_OVERHEAD_TOKENS}, "
                f"chunk={cls.MAX_CHUNK_TOKENS}, "
                f"output={cls.MAX_OUTPUT_TOKENS}, "
                f"margin={cls.SAFETY_MARGIN_TOKENS}"
            )

        if cls.MAX_CHUNK_TOKENS < 1 or cls.MAX_OUTPUT_TOKENS < 1:
            raise ValueError("Chunk and output token limits must be positive.")

        # Create required directories
        cls.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        cls.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


# Validate on import
Config.validate()
