"""Deterministic local Ollama client (no external API, no key).

Talks only to http://localhost:11434. temperature 0 and a fixed seed make
generations as reproducible as the backend allows. Records the exact model tag
and digest actually served.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen2.5:14b"
SEED = 20261107
TEMPERATURE = 0


class OllamaError(RuntimeError):
    pass


def _post(path: str, body: dict, timeout: float = 600) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL + path, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _get(path: str, timeout: float = 10) -> dict:
    with urllib.request.urlopen(OLLAMA_URL + path, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def server_version() -> str:
    return _get("/api/version").get("version", "?")


def model_fingerprint(model: str = MODEL) -> dict:
    """Return the served model's tag, digest and parameter size."""
    try:
        info = _post("/api/show", {"model": model}, timeout=30)
    except Exception as exc:  # pragma: no cover - network/environment dependent
        return {"model": model, "error": str(exc)}
    details = info.get("details", {})
    digest = ""
    for m in _get("/api/tags").get("models", []):
        if m.get("name") == model:
            digest = m.get("digest", "")
            break
    return {"model": model, "digest": digest,
            "parameter_size": details.get("parameter_size", ""),
            "quantization": details.get("quantization_level", ""),
            "family": details.get("family", "")}


class OllamaClient:
    def __init__(self, model: str = MODEL, seed: int = SEED, temperature: float = TEMPERATURE,
                 num_predict: int = 512, retries: int = 1):
        self.model = model
        self.seed = seed
        self.temperature = temperature
        self.num_predict = num_predict
        self.retries = retries
        self.calls = 0

    def generate(self, prompt: str, *, system: str | None = None, num_predict: int | None = None) -> str:
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature, "seed": self.seed,
                        "num_predict": num_predict or self.num_predict, "top_p": 1, "top_k": 1},
        }
        if system is not None:
            body["system"] = system
        last = None
        for attempt in range(self.retries + 1):
            try:
                out = _post("/api/generate", body)
                self.calls += 1
                return out.get("response", "")
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(1.0)
        raise OllamaError(f"ollama generate failed after {self.retries + 1} tries: {last}")
