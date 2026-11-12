"""Shared file tools. Any agent can use these to look at the code."""

from pathlib import Path

from langchain_core.tools import tool


def make_read_file(target: Path):
    """Create a read_file tool that can only see files inside `target`."""

    @tool
    def read_file(path: str) -> str:
        """Read one file from the project to look at the code around a finding.
        Use a path relative to the project folder, e.g. 'db.py'. Lines are numbered."""
        full_path = (target / path).resolve()
        if target not in full_path.parents:
            return "Error: that path is outside the project folder."
        if not full_path.is_file():
            return f"Error: {path} not found."
        lines = full_path.read_text(errors="ignore").splitlines()[:300]
        return "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))

    return read_file
