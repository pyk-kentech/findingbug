import json
from typing import Any

from .ollama_client import OllamaClient
from .prompts import HOLMES_SYSTEM_PROMPT


class SigmaTranslator:
    """Translate raw Sigma YAML into HOLMES JSON via Ollama."""

    def __init__(self, client: OllamaClient | None = None) -> None:
        self.client = client or OllamaClient()

    def translate(self, yaml_text: str, feedback: str | None = None) -> dict[str, Any]:
        prompt = (
            "Translate the following Sigma rule YAML into the required HOLMES JSON.\n\n"
            "[Sigma Rule YAML]\n"
            f"{yaml_text}"
        )
        if feedback:
            prompt = f"{prompt}\n\n{feedback}"
        response_text = self.client.generate(
            prompt=prompt,
            system=HOLMES_SYSTEM_PROMPT,
        )
        return json.loads(response_text)
