
"""One place to create the LLM, so every agent in the team uses the same setup."""

import os

from langchain_openai import ChatOpenAI


def get_llm():
    model = os.getenv("MODEL", "gpt-5-nano")
    settings = {"model": model, "api_key": os.environ["OPENAI_API_KEY"]}

    # Optional: point at a different OpenAI-compatible service later
    if os.getenv("LLM_BASE_URL"):
        settings["base_url"] = os.environ["LLM_BASE_URL"]

    # GPT-5 models only accept their default temperature, so only set it for others
    if not model.startswith("gpt-5"):
        settings["temperature"] = 0

    return ChatOpenAI(**settings)
