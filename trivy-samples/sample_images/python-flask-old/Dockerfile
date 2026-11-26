# Deliberately UNSAFE image for testing the Trivy agent. Do not use in real work.
#
# What Trivy should find:
#   - OS vulnerabilities: Debian "buster" base is end-of-life and has many known CVEs
#   - Python package vulnerabilities: old flask, requests, urllib3, jinja2
#   - Misconfigurations in this Dockerfile (see the comments marked "BAD")
#   - A secret written in plain text
#
# Build from the repo root:
#   docker build -t devsecops-sample/python-flask-old -f sample_images/python-flask-old/Dockerfile .

# BAD: old, end-of-life base image
FROM python:3.8-slim-buster

# BAD: secret written straight into the image
ENV API_KEY=sk-live-9f8e7d6c5b4a3210

WORKDIR /app

# BAD: ADD instead of COPY
ADD sample_images/python-flask-old/requirements.txt /app/requirements.txt

# BAD: no --no-cache-dir, and packages are old on purpose
RUN pip install -r requirements.txt

# BAD: apt-get without pinned versions, and the apt cache is not cleaned up
RUN apt-get update && apt-get install -y curl

ADD sample_app/ /app/

EXPOSE 5000

# BAD: no USER line, so the app runs as root
# BAD: no HEALTHCHECK
CMD ["python", "app.py"]
