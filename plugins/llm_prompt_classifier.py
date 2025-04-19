"""
Classifier using Semantic Kernel 1.x API.
"""
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion, OpenAIPromptExecutionSettings
from semantic_kernel.contents import ChatMessageContent, AuthorRole, ChatHistory
import asyncio

_SYSTEM = (
    "You are a security classifier. "
    "Output exactly SAFE or MALICIOUS."
)

class LLMPromptClassifier:
    def __init__(self, endpoint: str, api_key: str, deployment: str):
        self.chat_service = AzureChatCompletion(
            deployment_name=deployment,
            endpoint=endpoint,
            api_key=api_key
        )

    async def classify(self, prompt: str) -> str:
        try:
            async def _call():
                chat_history = ChatHistory()
                chat_history.add_message(ChatMessageContent(role=AuthorRole.SYSTEM, content=_SYSTEM))
                chat_history.add_message(ChatMessageContent(role=AuthorRole.USER, content=prompt))
                settings = OpenAIPromptExecutionSettings(
                    max_tokens=8,
                    temperature=0.0
                )
                result = await self.chat_service.get_chat_message_content(
                    chat_history,
                    settings
                )
                answer = result.content.strip().upper()
                if answer not in ("SAFE", "MALICIOUS"):
                    return f"ERROR: Unexpected LLM output: {answer}"
                return answer
            return await asyncio.wait_for(_call(), timeout=10)
        except asyncio.TimeoutError:
            return "ERROR: LLM classifier timeout"
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"
