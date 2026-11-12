# DevSecOps Agent Team

Each security job is its own small agent in `agents/`. Later, a supervisor
agent will call them and merge their reports.

| Agent | Status |
|-------|--------|
| Snyk (code + dependencies) | done |
| Trivy (IaC, containers) | next |
| Secrets (Gitleaks) | later |
| Supervisor | later |

## One-time setup (in a Codespace)

1. Snyk account: sign up free at snyk.io. In the Snyk web UI, make sure
   Snyk Code is turned on (Settings -> Snyk Code).
2. Get your Snyk token: Snyk web UI -> Account settings -> Auth Token.
   Then in the terminal:  export SNYK_TOKEN=<your token>
3. Node.js is needed for `npx` (Codespaces already has it).
4. pip install -r requirements.txt

## Dependency scan needs the packages installed

Snyk checks Python dependencies by looking at what is installed, so install the
sample app's (deliberately old) packages in their own virtual environment:

    python -m venv .venv-sample
    source .venv-sample/bin/activate
    pip install -r sample_app/requirements.txt
    pip install -r requirements.txt

## Run

    python run_snyk.py sample_app

## Folder layout

    common/llm.py         same LLM setup for every agent
    common/file_tools.py  shared read_file tool
    agents/snyk_agent.py  the Snyk specialist
    run_snyk.py           runs the Snyk agent on its own
    sample_app/           deliberately unsafe code to test with
