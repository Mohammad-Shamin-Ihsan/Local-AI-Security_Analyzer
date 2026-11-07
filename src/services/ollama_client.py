"""
Ollama client for local LLM inference.
Handles model communication with proper error handling and timeouts.
"""
import httpx
import logging
from typing import Dict, Any, Optional
from src.config import Config

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for communicating with Ollama API."""

    def __init__(self):
        self.base_url = Config.OLLAMA_HOST
        self.model = Config.OLLAMA_MODEL
        self.timeout = Config.OLLAMA_TIMEOUT
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=min(10, self.timeout))
        )

    async def test_connection(self) -> bool:
        """Test if Ollama is accessible and model is available."""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m["name"] for m in models]

                # Check if our model is available
                if self.model in model_names:
                    return True

                print(f"Warning: Model {self.model} not found in Ollama.")
                print(f"Available models: {model_names}")
                return False

            return False
        except (httpx.HTTPError, ValueError, KeyError) as e:
            logger.warning("Failed to connect to Ollama: %s", e)
            return False

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate completion from Ollama.

        Args:
            prompt: User prompt
            system: System prompt (optional)
            options: Model options (temperature, num_ctx, etc.)

        Returns:
            Generated text response

        Raises:
            httpx.TimeoutException: If request times out
            httpx.HTTPError: If request fails
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "think": False,
            "options": options or {
                "num_ctx": Config.MAX_CONTEXT_TOKENS,
                "num_predict": Config.MAX_OUTPUT_TOKENS,
                "temperature": 0.1,  # Low temperature for consistent output
                "top_p": 0.9,
                "num_thread": 2,  # Match assessment 2 vCPU
            }
        }

        if system:
            payload["system"] = system

        response = await self.client.post(
            f"{self.base_url}/api/generate",
            json=payload
        )
        response.raise_for_status()

        result = response.json()
        generated = result.get("response")
        if not isinstance(generated, str):
            raise ValueError("Ollama response did not contain generated text")
        return generated

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
