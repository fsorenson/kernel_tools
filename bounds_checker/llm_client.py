"""
LLM client abstraction for the bounds checker.

Supports Anthropic (Claude) and Google (Gemini) backends behind a unified
interface.  Higher-level code calls make_client() and LLMClient.generate();
provider-specific details are hidden here.

Provider selection:
  - GEMINI_API_KEY set          → Google Gemini
  - ANTHROPIC_VERTEX_PROJECT_ID → Anthropic via Vertex AI
  - ANTHROPIC_API_KEY           → Anthropic direct
  - None of the above           → RuntimeError
"""

import os
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""
    text: str = ''
    thinking: str = ''
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ''


class LLMClient:
    """Uniform interface wrapping a specific provider."""

    def __init__(self, provider, raw_client, default_model=None):
        self.provider = provider          # 'anthropic' | 'gemini'
        self._client = raw_client
        self.default_model = default_model

    def generate(self, *, model=None, system, prompt, max_tokens,
                 thinking_budget=0) -> LLMResponse:
        model = model or self.default_model
        if self.provider == 'anthropic':
            return _anthropic_generate(
                self._client, model, system, prompt, max_tokens, thinking_budget)
        if self.provider == 'gemini':
            return _gemini_generate(
                self._client, model, system, prompt, max_tokens, thinking_budget)
        raise ValueError(f"unknown provider: {self.provider}")


def make_client(model=None):
    """
    Build an LLMClient from environment variables.

    Returns (client, resolved_model).
    """
    # Gemini via Vertex AI (GOOGLE_CLOUD_PROJECT + application default credentials)
    gcp_project = os.environ.get('GOOGLE_CLOUD_PROJECT')
    if gcp_project:
        from google import genai
        location = os.environ.get('GOOGLE_CLOUD_LOCATION', 'us-central1')
        client = genai.Client(vertexai=True, project=gcp_project, location=location)
        resolved = model or os.environ.get(
            'GEMINI_DEFAULT_MODEL', 'gemini-2.5-flash')
        return LLMClient('gemini', client, resolved), resolved

    # Gemini via API key
    gemini_key = os.environ.get('GEMINI_API_KEY')
    if gemini_key:
        from google import genai
        client = genai.Client(api_key=gemini_key)
        resolved = model or os.environ.get(
            'GEMINI_DEFAULT_MODEL', 'gemini-2.5-flash')
        return LLMClient('gemini', client, resolved), resolved

    # Anthropic — Vertex AI
    project_id = os.environ.get('ANTHROPIC_VERTEX_PROJECT_ID')
    if project_id:
        from anthropic import AnthropicVertex
        region = os.environ.get('CLOUD_ML_REGION', 'us-east5')
        if region == 'global':
            region = 'us-east5'
        client = AnthropicVertex(project_id=project_id, region=region)
        resolved = model or os.environ.get(
            'ANTHROPIC_DEFAULT_SONNET_MODEL', 'claude-sonnet-4-6')
        return LLMClient('anthropic', client, resolved), resolved

    # Anthropic — direct API key
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if api_key:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        resolved = model or os.environ.get(
            'ANTHROPIC_DEFAULT_SONNET_MODEL', 'claude-sonnet-4-6')
        return LLMClient('anthropic', client, resolved), resolved

    raise RuntimeError(
        'No LLM credentials found.  Set one of:\n'
        '  GOOGLE_CLOUD_PROJECT          — Gemini via Vertex AI (uses ADC)\n'
        '  GEMINI_API_KEY                — Gemini via API key\n'
        '  ANTHROPIC_VERTEX_PROJECT_ID   — Anthropic via Vertex AI\n'
        '  ANTHROPIC_API_KEY             — Anthropic direct API'
    )


# ---------------------------------------------------------------------------
# Anthropic backend
# ---------------------------------------------------------------------------

def _anthropic_generate(client, model, system, prompt, max_tokens,
                        thinking_budget):
    kwargs = dict(
        model=model,
        max_tokens=max_tokens + thinking_budget if thinking_budget else max_tokens,
        system=system,
        messages=[{'role': 'user', 'content': prompt}],
    )
    if thinking_budget:
        kwargs['thinking'] = {'type': 'enabled', 'budget_tokens': thinking_budget}

    msg = client.messages.create(**kwargs)

    resp = LLMResponse()
    for block in msg.content:
        if block.type == 'thinking':
            resp.thinking = block.thinking
        elif block.type == 'text':
            resp.text = block.text.strip()

    resp.stop_reason = msg.stop_reason or ''
    resp.input_tokens = msg.usage.input_tokens
    resp.output_tokens = msg.usage.output_tokens
    return resp


# ---------------------------------------------------------------------------
# Gemini backend
# ---------------------------------------------------------------------------

_GEMINI_TOKEN_MULTIPLIER = 3
_GEMINI_TOKEN_FLOOR = 16384

def _gemini_generate(client, model, system, prompt, max_tokens,
                     thinking_budget):
    from google.genai import types

    output_tokens = max(max_tokens * _GEMINI_TOKEN_MULTIPLIER, _GEMINI_TOKEN_FLOOR)
    config = types.GenerateContentConfig(
        system_instruction=system,
        max_output_tokens=output_tokens,
    )
    if thinking_budget:
        config.thinking_config = types.ThinkingConfig(
            include_thoughts=True,
            thinking_budget=thinking_budget,
        )

    resp_msg = client.models.generate_content(
        model=model,
        contents=prompt,
        config=config,
    )

    resp = LLMResponse()
    if resp_msg.candidates:
        for part in resp_msg.candidates[0].content.parts:
            if getattr(part, 'thought', False):
                resp.thinking = part.text or ''
            elif part.text is not None:
                resp.text = (resp.text + part.text).strip()

    finish = resp_msg.candidates[0].finish_reason if resp_msg.candidates else ''
    # Normalize to Anthropic-style stop reasons for uniform handling.
    _REASON_MAP = {'STOP': 'end_turn', 'MAX_TOKENS': 'max_tokens'}
    raw = finish.name if hasattr(finish, 'name') else str(finish)
    resp.stop_reason = _REASON_MAP.get(raw, raw)

    usage = resp_msg.usage_metadata
    if usage:
        resp.input_tokens = usage.prompt_token_count or 0
        resp.output_tokens = usage.candidates_token_count or 0
    return resp
