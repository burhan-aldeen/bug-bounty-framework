import os

from core.logger import get_logger

logger = get_logger("agent")

try:
    from ollama import AsyncClient
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False
    AsyncClient = None

try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    AsyncOpenAI = None


SUMMARIZE_PROMPT = (
    "You are a bug bounty report assistant. "
    "Given the following findings, produce a concise technical summary "
    "with impact assessment and recommended remediation. "
    "Respond in plain text without markdown formatting."
)


async def query_ollama(prompt: str, model: str = "qwen3.5:9b", url: str = "http://localhost:11434", timeout: int = 120) -> str | None:
    if not HAS_OLLAMA:
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


async def query_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini", timeout: int = 60) -> str | None:
    if not HAS_OPENAI:
        return None
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return None
    client = AsyncOpenAI(api_key=api_key, timeout=timeout)
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.choices[0].message.content
        if content:
            logger.info("openai response received (%d chars)", len(content))
            return content
        logger.warning("openai returned empty response")
        return None
    except Exception as exc:
        logger.warning("openai request failed: %s", exc)
        return None


async def generate_ai_summary(
    findings_text: str,
    model: str = "",
    url: str = "",
    api_key: str = "",
) -> str | None:
    prompt = f"{SUMMARIZE_PROMPT}\n\n{findings_text}"

    result = await query_ollama(prompt, model=model or "qwen3.5:9b", url=url or "http://localhost:11434")
    if result:
        return result

    result = await query_openai(prompt, api_key=api_key, model=model or "gpt-4o-mini")
    if result:
        return result

    logger.warning("no AI backend available (install openai package or start ollama)")
    return None
