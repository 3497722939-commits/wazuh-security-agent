"""
LLM 客户端：OpenAI 兼容接口，支持 function calling。
"""
import os
from openai import OpenAI


class LLMClient:
    def __init__(self):
        self.client = OpenAI(
            base_url=os.getenv("LLM_BASE_URL", "https://ai.lupoapi.com/v1"),
            api_key=os.getenv("LLM_API_KEY", ""),
        )
        self.model = os.getenv("LLM_MODEL", "gpt-5.5")

    def chat(self, messages, tools=None, temperature=0.3):
        """调用 LLM，返回完整响应。"""
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return self.client.chat.completions.create(**kwargs)
