FROM python:3.12-slim

WORKDIR /app

# Install git (needed for pip install from github)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt pyproject.toml setup.cfg* ./
COPY src/ src/
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Create data directory for credential storage
RUN mkdir -p /data

EXPOSE 8000

# Container defaults - SSE transport
ENV MCP_TRANSPORT=sse
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
ENV MONARCH_DATA_DIR=/data

VOLUME /data

CMD ["python", "src/monarch_mcp_server/server.py"]
