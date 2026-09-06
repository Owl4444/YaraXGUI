# YaraXGUI — headless REST API server
# Builds a slim image running the FastAPI app (api.yaraxgui_api:app).
# No PySide6/Qt, keyring, or pyinstaller — server code does not import them.

FROM python:3.12-slim

# Non-root user
RUN groupadd -g 1000 yaraxgui && useradd -u 1000 -g yaraxgui -d /app -s /usr/sbin/nologin yaraxgui

WORKDIR /app

# Install server-only Python deps first for better layer caching
COPY requirements-server.txt ./
COPY modules/yarax-editor/ ./modules/yarax-editor/
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2" \
    && python -m pip install --no-cache-dir -r requirements-server.txt

# Copy the parts of the repo the API actually needs
COPY api/ ./api/
COPY plugins/ ./plugins/
COPY hex_editor/ ./hex_editor/
COPY yaraxgui/ ./yaraxgui/

# Data lives on a mounted volume (rule DB + uploads)
ENV YARAXGUI_REPO_DB=/data/rules.db \
    YARAXGUI_UPLOAD_DIR=/data/uploads \
    YARAXGUI_ALLOWED_ROOTS=/data/samples \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data/uploads /data/samples && chown -R yaraxgui:yaraxgui /app /data

USER yaraxgui

EXPOSE 7777

CMD ["python", "-m", "api.server"]
