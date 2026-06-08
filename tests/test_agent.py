import pytest

from core.agent import HAS_OLLAMA, query_ollama, generate_ai_summary


class TestAgent:
    @pytest.mark.asyncio
    async def test_query_ollama_no_package(self) -> None:
        result = await query_ollama("test prompt")
        if not HAS_OLLAMA:
            assert result is None
        else:
            assert result is None or isinstance(result, str)

    @pytest.mark.asyncio
    async def test_generate_ai_summary_no_package(self) -> None:
        result = await generate_ai_summary("found XSS at /test")
        if not HAS_OLLAMA:
            assert result is None
        else:
            assert result is None or isinstance(result, str)

    @pytest.mark.asyncio
    async def test_query_ollama_custom_params(self) -> None:
        result = await query_ollama(
            "test", model="test-model", url="http://nonexistent:11434", timeout=1
        )
        if HAS_OLLAMA:
            assert result is None
        else:
            assert result is None

    def test_prompt_constant(self) -> None:
        from core.agent import SUMMARIZE_PROMPT
        assert "bug bounty" in SUMMARIZE_PROMPT.lower()
