"""Pluggable LLM client for grounded concept extraction.

Supports multiple model backends, selected via EVIDENCE_LLM_PROVIDER:
  - "anthropic"   -> Anthropic Messages API (needs ANTHROPIC_API_KEY)
  - "huggingface" -> HuggingFace Inference API, free tier (needs HF_API_TOKEN)
  - "none"        -> disabled; caller falls back to deterministic lexicon matching
  - "auto"        -> (default) anthropic if its key is set, else huggingface if its
                     token is set, else none.

Whatever backend is used, the model is asked to return ONLY concepts that are
backed by a verbatim quote from the source. The caller (evidence_graph.extract)
re-verifies every quote and validates every concept id against the closed-set
lexicon, so a weak/free model cannot inject ungrounded or invented links — it can
only reduce recall. Decoding is greedy / temperature-capped for reproducibility.

NOTE: the HuggingFace path is written to HF's documented Inference API contract but
must be exercised against the live service after deployment; free-tier model
availability and rate limits vary, which is exactly why the lexicon fallback exists.
"""
from __future__ import annotations

import json
import os
from typing import Any

import requests

PROMPT_VERSION = "evidence-extract-v2"

_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
_HF_ENDPOINT = "https://api-inference.huggingface.co/models/{model}"


# ---------------------------------------------------------------- config
def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def provider() -> str:
    """Resolve the active backend name: 'anthropic' | 'huggingface' | 'none'."""
    p = _env("EVIDENCE_LLM_PROVIDER", "auto").lower()
    if p in ("hf", "huggingface"):
        return "huggingface"
    if p == "anthropic":
        return "anthropic"
    if p == "none":
        return "none"
    # auto
    if _env("ANTHROPIC_API_KEY"):
        return "anthropic"
    if _env("HF_API_TOKEN") or _env("HUGGINGFACE_API_TOKEN"):
        return "huggingface"
    return "none"


def _temperature() -> float:
    """User requirement: strict 0-0.1. Default 0; clamp to that range."""
    try:
        t = float(_env("EVIDENCE_LLM_TEMPERATURE", "0"))
    except ValueError:
        t = 0.0
    return max(0.0, min(0.1, t))


def available() -> bool:
    return provider() != "none"


def active_model() -> str:
    p = provider()
    if p == "anthropic":
        return _env("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    if p == "huggingface":
        return _env("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
    return "lexicon"


# ---------------------------------------------------------------- prompt (shared)
_INSTRUCTION = (
    "You are a compliance evidence extractor. You are given a DOCUMENT and a fixed "
    "list of COMPLIANCE CONCEPTS. Identify which concepts are genuinely evidenced by "
    "the document's text. For each evidenced concept output: its exact concept id "
    "(only ids from the provided list), the EXACT verbatim quote copied "
    "character-for-character from the document that evidences it, and a confidence "
    "from 0 to 1. Only include a concept when a real supporting quote exists in the "
    "document. Do not invent quotes or concept ids. Respond with ONLY a JSON array of "
    'objects {"concept_id","quote","confidence"} and nothing else.'
)


def _catalog_str(concepts: list[dict[str, Any]]) -> str:
    return "\n".join(
        f"- {c['id']}: {c['label']} (aliases: {', '.join(c.get('aliases', [])[:5])})"
        for c in concepts
    )


def _user_prompt(doc_text: str, concepts: list[dict[str, Any]], max_chars: int) -> str:
    return (f"COMPLIANCE CONCEPTS:\n{_catalog_str(concepts)}\n\n"
            f"DOCUMENT:\n\"\"\"\n{doc_text[:max_chars]}\n\"\"\"\n\n"
            "Return the JSON array now.")


def _parse_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract and normalise a JSON array of hits from raw model text."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except Exception:
        return None
    out: list[dict[str, Any]] = []
    for item in parsed:
        if isinstance(item, dict) and item.get("concept_id") and item.get("quote"):
            try:
                conf = float(item.get("confidence", 0.7))
            except (TypeError, ValueError):
                conf = 0.7
            out.append({"concept_id": str(item["concept_id"]),
                        "quote": str(item["quote"]),
                        "confidence": conf})
    return out


# ---------------------------------------------------------------- backends
def _detect_anthropic(doc_text, concepts, max_chars):
    body = {
        "model": _env("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        "max_tokens": 2000,
        "temperature": _temperature(),
        "system": _INSTRUCTION,
        "messages": [{"role": "user", "content": _user_prompt(doc_text, concepts, max_chars)}],
    }
    headers = {"x-api-key": _env("ANTHROPIC_API_KEY"),
               "anthropic-version": "2023-06-01", "content-type": "application/json"}
    r = requests.post(_ANTHROPIC_ENDPOINT, headers=headers, json=body, timeout=60)
    if r.status_code != 200:
        return None
    data = r.json()
    text = "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text")
    return _parse_json_array(text)


def _detect_huggingface(doc_text, concepts, max_chars):
    token = _env("HF_API_TOKEN") or _env("HUGGINGFACE_API_TOKEN")
    model = _env("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
    # Many instruct models follow a single combined prompt; keep it backend-agnostic.
    prompt = _INSTRUCTION + "\n\n" + _user_prompt(doc_text, concepts, max_chars)
    body = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 1500,
            "return_full_text": False,
            "do_sample": False,            # greedy -> reproducible (temp-0 equivalent)
            "temperature": max(0.01, _temperature()),  # HF rejects exactly 0 for some models
        },
        "options": {"wait_for_model": True, "use_cache": True},
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(_HF_ENDPOINT.format(model=model), headers=headers, json=body, timeout=120)
    if r.status_code != 200:
        return None
    data = r.json()
    # HF text-generation returns [{"generated_text": "..."}]; some return a dict on error.
    if isinstance(data, list) and data and isinstance(data[0], dict):
        text = data[0].get("generated_text", "")
    elif isinstance(data, dict) and "generated_text" in data:
        text = data["generated_text"]
    else:
        return None
    return _parse_json_array(text)


# ---------------------------------------------------------------- public api
def detect_concepts(doc_text: str, concepts: list[dict[str, Any]],
                    max_chars: int = 16000) -> list[dict[str, Any]] | None:
    """Return [{concept_id, quote, confidence}] or None if unavailable / failed.

    Returning None signals the caller to fall back to deterministic lexicon matching.
    """
    p = provider()
    if p == "none":
        return None
    try:
        if p == "anthropic":
            return _detect_anthropic(doc_text, concepts, max_chars)
        if p == "huggingface":
            return _detect_huggingface(doc_text, concepts, max_chars)
    except Exception:
        return None
    return None
