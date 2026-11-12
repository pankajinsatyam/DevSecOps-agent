"""
Run the Snyk agent on its own.

    python run_snyk.py sample_app                               # a local folder
    python run_snyk.py https://github.com/<owner>/<repo>.git     # a repo URL
"""

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

from langchain_core.messages import HumanMessage

from agents.snyk_agent import build_snyk_agent, load_snyk_tools
from common.file_tools import make_read_file
from common.llm import get_llm


def get_target(arg: str) -> Path:
    """If arg is a git URL, clone it to a temp folder. Otherwise treat it as a local folder."""
    if arg.startswith(("https://", "git@")):
        folder = Path(tempfile.mkdtemp()) / "repo"
        print(f"Cloning {arg} ...")
        subprocess.run(["git", "clone", "--depth", "1", arg, str(folder)], check=True)
        return folder.resolve()
    return Path(arg).resolve()


async def main():
    target = get_target(sys.argv[1] if len(sys.argv) > 1 else "sample_app")
    print(f"Snyk agent scanning: {target}\n")

    tools = await load_snyk_tools() + [make_read_file(target)]
    print("Tools loaded:", ", ".join(t.name for t in tools), "\n")

    agent = build_snyk_agent(get_llm(), tools)
    start = {"messages": [HumanMessage(f"Scan the project at this absolute path: {target}")]}
    report = ""

    async for update in agent.astream(start, {"recursion_limit": 25}, stream_mode="updates"):
        for node, data in update.items():
            msg = data["messages"][-1]
            if node == "agent" and msg.tool_calls:
                for call in msg.tool_calls:
                    print(f"  -> calls {call['name']}({call['args']})")
            elif node == "agent":
                report = msg.content

    print("\n========== SNYK REPORT ==========\n")
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
