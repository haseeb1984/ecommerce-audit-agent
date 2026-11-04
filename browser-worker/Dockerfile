FROM mcr.microsoft.com/playwright/python:v1.56.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /srv/browser-worker
COPY browser-worker/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --requirement requirements.txt
COPY browser_audit_service.py ./browser_audit_service.py

RUN useradd --create-home --shell /bin/bash pwuser && chown -R pwuser:pwuser /srv/browser-worker
ENV HOME=/home/pwuser
USER pwuser
EXPOSE 8080
CMD ["uvicorn", "browser_audit_service:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
