# The "good" version of python-flask-old, so you can compare the two Trivy reports.
# Trivy should find far fewer problems here.
#
# What changed:
#   - Current, supported base image (Debian bookworm, Python 3.12)
#   - No secrets in the image (pass API_KEY at run time instead)
#   - COPY instead of ADD, --no-cache-dir for pip
#   - Runs as a normal user, not root
#   - Has a HEALTHCHECK
#
# Note: the image still contains sample_app's code, which has a hard-coded key in
# app.py on purpose. Trivy's secret scanner may still flag that one file.
#
# Build from the repo root:
#   docker build -t devsecops-sample/python-flask-fixed -f sample_images/python-flask-fixed/Dockerfile .

FROM python:3.12-slim-bookworm

WORKDIR /app

COPY sample_images/python-flask-fixed/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sample_app/ /app/

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import socket; socket.create_connection(('localhost', 5000), 2)" || exit 1

CMD ["python", "app.py"]
