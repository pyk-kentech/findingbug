import os
from typing import Any

import requests


class OllamaClient:
    """Minimal Ollama REST client configured via environment variables."""

    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "qwen2.5-coder:14b"
    GENERATE_PATH = "/api/generate"
    FORMAT = "json"
    OPTIONS = {
        "temperature": 0.0,
        "top_p": 0.1,
        "num_ctx": 4096,
    }

    def __init__(self, base_url: str | None = None, timeout: float = 120.0) -> None:
        resolved_base_url = base_url or os.getenv("OLLAMA_URL", self.DEFAULT_BASE_URL)
        self.base_url = resolved_base_url.rstrip("/")
        self.model = os.getenv("OLLAMA_MODEL", self.DEFAULT_MODEL)
        self.timeout = timeout

    def generate(self, prompt: str, system: str | None = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "format": self.FORMAT,
            "options": self.OPTIONS,
            "stream": False,
        }
        if system is not None:
            payload["system"] = system

        response = requests.post(
            f"{self.base_url}{self.GENERATE_PATH}",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()

        data = response.json()
        generated_text = data.get("response")
        if not isinstance(generated_text, str):
            raise ValueError("Ollama response did not include a string 'response' field.")

        return generated_text
