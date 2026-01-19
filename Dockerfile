FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --upgrade pip && \
    pip install --no-cache-dir .

CMD ["python", "-m", "mcp_scansage.mcp.server"]
