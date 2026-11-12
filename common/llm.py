"""One place to create the LLM, so every agent in the team uses the same setup."""

import os

from langchain_openai import ChatOpenAI


def get_llm():
    return ChatOpenAI(
        model=os.getenv("MODEL", "openai/gpt-4o-mini"),
        base_url="https://models.github.ai/inference",  # GitHub Models (free in Codespaces)
        api_key=os.environ["GITHUB_TOKEN"],
        temperature=0,  # same code -> same answer, important for security checks
    )
