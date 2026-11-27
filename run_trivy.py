"""
Run the Trivy agent on its own. It works out what kind of target you gave it:

    python run_trivy.py trivy-samples/sample_images                          # a local folder
    python run_trivy.py trivy-samples/sample_sbom/java-orders-service.cdx.json  # an SBOM file
    python run_trivy.py python:3.8-slim-buster                               # a container image
    python run_trivy.py https://github.com/<owner>/<repo>                    # a git repo URL
"""

import asyncio
import sys
from pathlib import Path

from langchain_core.messages import HumanMessage

from agents.trivy_agent import build_trivy_agent, make_scan_sbom, trivy_tools
from common.file_tools import make_read_file
from common.llm import get_llm

SBOM_ENDINGS = (".cdx.json", ".spdx.json", ".spdx", ".sbom.json", "bom.json")


def get_target(arg: str):
    """Return (kind, target, extra_tools) for the given argument."""
    if arg.startswith("https://"):
        return "git repo URL", arg, []

    path = Path(arg)
    if path.is_dir():
        folder = path.resolve()
        return "folder", str(folder), [make_read_file(folder)]
    if path.is_file():
        if not arg.endswith(SBOM_ENDINGS):
            sys.exit(f"{arg} is a file, but not an SBOM (expected one of: {', '.join(SBOM_ENDINGS)})")
        sbom = path.resolve()
        return "SBOM file", str(sbom), [make_scan_sbom(sbom)]

    # Not a folder, not a file, not a URL: treat it as a container image name like nginx:1.19
    return "container image", arg, []


async def main():
    kind, target, extra_tools = get_target(sys.argv[1] if len(sys.argv) > 1 else "trivy-samples/sample_images")
    print(f"Trivy agent scanning ({kind}): {target}\n")

    # Everything happens inside one Trivy session, so findings_list can read the scan results
    async with trivy_tools() as mcp_tools:
        # For an SBOM we only need our own scan_sbom tool
        tools = extra_tools if kind == "SBOM file" else mcp_tools + extra_tools
        print("Tools loaded:", ", ".join(t.name for t in tools), "\n")

        agent = build_trivy_agent(get_llm(), tools)
        start = {"messages": [HumanMessage(f"Scan this {kind}: {target}")]}
        report = ""

        async for update in agent.astream(start, {"recursion_limit": 25}, stream_mode="updates"):
            for node, data in update.items():
                msg = data["messages"][-1]
                if node == "agent" and msg.tool_calls:
                    for call in msg.tool_calls:
                        print(f"  -> calls {call['name']}({call['args']})")
                elif node == "agent":
                    report = msg.content

    print("\n========== TRIVY REPORT ==========\n")
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
