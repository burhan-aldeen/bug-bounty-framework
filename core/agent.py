from core.logger import get_logger

logger = get_logger("agent")

try:
    from ollama import AsyncClient

    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False
    AsyncClient = None  # type: ignore


OLLAMA_SUMMARIZE_PROMPT: str = (
    "You are a bug bounty report assistant. "
    "Given the following findings, produce a concise technical summary "
    "with impact assessment and recommended remediation. "
    "Respond in plain text without markdown formatting."
)


async def query_ollama(
    prompt: str,
    model: str = "qwen3.5:9b",
    url: str = "http://localhost:11434",
    timeout: int = 120,
) -> str | None:
    if not HAS_OLLAMA:
        logger.warning("ollama package not installed, skipping AI analysis")
        return None

    client = AsyncClient(host=url, timeout=timeout)
    try:
        response = await client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.get("message", {}).get("content", "")
        if content:
            logger.info("ollama response received (%d chars)", len(content))
            return content
        logger.warning("ollama returned empty response")
        return None
    except Exception as exc:
        logger.warning("ollama request failed: %s", exc)
        return None


async def generate_ai_summary(
    findings_text: str,
    model: str = "qwen3.5:9b",
    url: str = "http://localhost:11434",
) -> str | None:
    prompt = f"{OLLAMA_SUMMARIZE_PROMPT}\n\n{findings_text}"
    return await query_ollama(prompt, model=model, url=url)
