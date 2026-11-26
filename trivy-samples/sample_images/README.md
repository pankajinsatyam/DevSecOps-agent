# Sample Docker images

Test targets for the Trivy agent. They are **unsafe on purpose**. Do not use them in real work.

| Folder | What it is | What Trivy should find |
|--------|------------|------------------------|
| `python-flask-old/` | Runs `sample_app` on an end-of-life Debian base | OS CVEs, old Python packages, Dockerfile misconfigs, a secret in `ENV` |
| `node-express-old/` | Small Express app on end-of-life Node 14 | OS CVEs, old npm packages (lodash, express, minimist, jsonwebtoken), Dockerfile misconfigs |
| `python-flask-fixed/` | The "good" version of `python-flask-old` | Far fewer findings, for comparison |
| `public_images.txt` | Public images on Docker Hub | Scan these by name, no build needed |

## Two ways to use them

**1. Scan the Dockerfiles without building anything.**
Trivy reads the Dockerfiles and lock files directly and reports misconfigurations
and package CVEs:

    trivy fs --scanners vuln,misconfig,secret sample_images

(By default `trivy fs` skips misconfigurations, so the `--scanners` flag matters.)

**2. Build the images, then scan the images.**
This also finds problems in the operating system layers. Run the build from the repo root:

    docker build -t devsecops-sample/python-flask-old   -f sample_images/python-flask-old/Dockerfile .
    docker build -t devsecops-sample/python-flask-fixed -f sample_images/python-flask-fixed/Dockerfile .
    docker build -t devsecops-sample/node-express-old   sample_images/node-express-old

    trivy image devsecops-sample/python-flask-old

Or skip the build and scan a public image straight away:

    trivy image python:3.8-slim-buster
