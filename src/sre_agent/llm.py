"""Optional LLM narration layer.

If SRE_AGENT_LLM_URL and SRE_AGENT_API_KEY are set (any OpenAI-compatible
chat-completions endpoint), the agent asks the model to write a two-sentence
on-call summary of the deterministic report. The LLM never classifies or
changes severity — that stays rule-based so triage is reproducible.
"""
from __future__ import annotations

import json
import os
import urllib.request


def llm_available() -> bool:
    return bool(os.environ.get("SRE_AGENT_LLM_URL") and os.environ.get("SRE_AGENT_API_KEY"))


def narrate(report_markdown: str, model: str = "gpt-4o-mini") -> str | None:
    """Return a short on-call summary, or None when no endpoint is configured."""
    if not llm_available():
        return None
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system",
             "content": "You are an on-call SRE. Summarise the incident report in two "
                        "sentences for a paging channel: what is happening and the first action."},
            {"role": "user", "content": report_markdown},
        ],
    }).encode()
    request = urllib.request.Request(
        os.environ["SRE_AGENT_LLM_URL"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['SRE_AGENT_API_KEY']}",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode())
    return body["choices"][0]["message"]["content"]
