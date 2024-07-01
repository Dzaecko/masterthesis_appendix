import semantic_kernel as sk
from dotenv import dotenv_values
from semantic_kernel.connectors.ai.open_ai import (
    OpenAITextCompletion,
    AzureTextCompletion,
    OpenAIChatCompletion,
    AzureChatCompletion,
)
from semantic_kernel.kernel import Kernel


def add_completion_service(self):
    config = dotenv_values(".env")
    llm_service = config.get("GLOBAL__LLM_SERVICE", None)

   
    model_id = config.get("OPEN_AI__MODEL_TYPE", None)

    if model_id == "chat-completion":
            self.add_chat_service(
                "chat_completion",
                OpenAIChatCompletion(
                    config.get("OPEN_AI__CHAT_COMPLETION_MODEL_ID", None),
                    api_key=config.get("sk-cMxDsDp144VvVribOZ3Vp", None),
                    org_id=config.get("org-FHIJxPxEFCUkRorE5H", None),
                ),
            )
    else:
            self.add_text_completion_service(
                "text_completion",
                OpenAITextCompletion(
                    config.get("OPEN_AI__TEXT_COMPLETION_MODEL_ID", None),
                    api_key=config.get("sk-cMlFx4VvVribOZ3Vp", None),
                    org_id=config.get("org-FHIxFCUkRorE5H", None),
                ),
            )


Kernel.add_completion_service = add_completion_service