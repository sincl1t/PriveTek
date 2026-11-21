FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN python -m pip install --no-cache-dir -r requirements-dev.txt && python -m pip check
# Explicit product inputs: do not copy .env, .venv, credentials or local databases.
COPY *.py ./
COPY DejaVuSansCondensed.ttf ./
COPY assets/ ./assets/
COPY account_ui/ ./account_ui/
COPY migrations/ ./migrations/
COPY tools/ ./tools/
RUN python -c "import uvicorn, fastapi; assert callable(uvicorn.run); assert callable(fastapi.FastAPI); from pathlib import Path; assert Path('server.py').stat().st_size > 0"
ENTRYPOINT ["python", "-X", "utf8", "tools/source_audit_stand/app.py"]
