"""
llm_client.py

Thin, provider-agnostic wrapper around an LLM API. The rest of the
synthesis layer never talks to a vendor SDK directly — it calls
`LlmClient.complete()`, so swapping providers later means changing only
this file.

Default provider is Google Gemini (free tier), decided at project
planning time. Model defaults to `gemini-2.5-flash` (free-tier quota:
10 req/min, 250 req/day) rather than `gemini-2.5-pro` (5 req/min,
50 req/day). Model can be overridden via the GEMINI_MODEL env var or
the constructor argument.

Security notes:
  - The API key is read from the GEMINI_API_KEY env var. It is never
    hardcoded and never written to any file the pipeline produces, so it
    can't leak into the benchmark output or a report.
  - Free tier may be used by Google to improve their products, so only
    synthetic/sample scan data should ever be sent here — never real
    client or production scan data — unless billing is enabled.

A deterministic MockClient is provided for offline development and for
tests. It is deliberately NOT used in production paths; it exists so the
hallucination harness can be exercised without burning quota or needing
network access. Its output is fixed per-prompt so benchmark behavior is
reproducible.
"""

import os
import sys
import time
from typing import Optional, Protocol

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:
    genai = None

DEFAULT_MODEL = "gemini-3.6-flash"
MAX_RETRIES = int(os.environ.get("GEMINI_MAX_RETRIES", 12))
RETRY_BASE_DELAY_S = float(os.environ.get("GEMINI_RETRY_BASE_DELAY_S", 12.0))
# Backwards-compat aliases — existing callers import DEFAULT_*
DEFAULT_MAX_RETRIES = MAX_RETRIES
DEFAULT_RETRY_BASE_DELAY_S = RETRY_BASE_DELAY_S


def _is_rate_limit(err: Exception) -> bool:
    """Detect a 429/rate-limit response regardless of SDK error shape."""
    text = f"{type(err).__name__}: {err}"
    lowered = text.lower()
    return ("429" in text or "resource_exhausted" in lowered
            or "rate limit" in lowered or "quota" in lowered)


def _server_retry_delay(err: Exception) -> Optional[float]:
    """Extract the server-recommended retry delay (seconds), if provided.

    Gemini 429 responses carry `Please retry in Ns.`; honoring it beats
    guessing, and it is what actually avoids further 429s during a long
    benchmark run.
    """
    import re
    text = f"{err}"
    m = re.search(r"retry in ([\d.]+)s", text, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


class LlmClient(Protocol):
    """The narrow interface the synthesis layer depends on."""

    def complete(self, prompt: str) -> str:
        """Return the model's text response to a single prompt."""
        ...


class GeminiClient:
    """Gemini-backed client. API key from GEMINI_API_KEY env var only."""

    def __init__(self, model: Optional[str] = None, max_retries: int = MAX_RETRIES):
        if genai is None:
            print(
                "GeminiClient requires the 'google-genai' package: pip install google-genai",
                file=sys.stderr,
            )
            raise RuntimeError("google-genai not installed")
        self.model = model or os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY env var is not set. Set it before running synthesis."
            )
        self._client = genai.Client(api_key=api_key)
        self.max_retries = max_retries
        # Public counters so the caller can report network behavior without
        # reaching into SDK internals.
        self.rate_limit_retries = 0
        self.network_errors = 0

    def complete(self, prompt: str) -> str:
        # Ask for the response as JSON so the synthesis layer can parse
        # structured fields reliably. The prompt itself also instructs the
        # model to emit JSON; this config makes the provider enforce it.
        config = genai_types.GenerateContentConfig(response_mime_type="application/json")

        attempt = 0
        delay = RETRY_BASE_DELAY_S
        while True:
            try:
                response = self._client.models.generate_content(
                    model=self.model, contents=prompt, config=config
                )
                return response.text
            except Exception as e:  # noqa: BLE001 — network/provider errors handled below
                attempt += 1
                if _is_rate_limit(e):
                    self.rate_limit_retries += 1
                else:
                    self.network_errors += 1
                if attempt > self.max_retries:
                    raise
                server_delay = _server_retry_delay(e)
                # A server delay of minutes+ (not a second-scale burst) means we
                # hit the *daily* quota boundary, which will not clear within
                # this run. Fail fast so the record is saved as ok:false and the
                # resumable runner re-tries it next calendar day instead of
                # sleeping through this run's remaining wall clock.
                if server_delay is not None and server_delay > 300.0:
                    print(
                        "  daily-quota exhaustion detected "
                        f"(server retry = {server_delay:.0f}s); failing fast for resume",
                        file=sys.stderr,
                    )
                    raise
                wait = max(delay, server_delay or 0.0) + 2.0
                print(
                    f"  retry {attempt}/{self.max_retries} for "
                    f"{type(e).__name__} (rate_limit={_is_rate_limit(e)}"
                    f", server_retry_delay={server_delay}s) "
                    f"in {wait:.0f}s",
                    file=sys.stderr,
                )
                time.sleep(wait)
                delay = min(max(delay * 1.6, wait), 90.0)


class MockClient:
    """
    Deterministic fake for offline runs and tests.

    Produces a fixed JSON response per prompt. The reply echoes any CVE
    IDs found in the prompt text — this lets the harness verify the
    set-membership logic without a network call, and it makes a good
    "grounded, perfectly compliant" baseline to sanity-check the pipeline.
    """

    def __init__(self):
        import re
        self._cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    def complete(self, prompt: str) -> str:
        import json
        cves = sorted(set(self._cve_pattern.findall(prompt)))
        explanation = (
            "This finding exposes a known vulnerability on the affected service. "
            "Apply the referenced remediation and verify the fix."
        )
        payload = {
            "plain_language_explanation": explanation,
            "cve_ids_mentioned": cves,
            "cis_controls_referenced": [],
            "remediation_steps": ["Patch the affected software", "Re-scan to verify"],
        }
        return json.dumps(payload)


def make_client(model: Optional[str] = None, offline: bool = False) -> LlmClient:
    """Factory: offline=True returns the deterministic MockClient."""
    if offline:
        return MockClient()
    return GeminiClient(model=model)
