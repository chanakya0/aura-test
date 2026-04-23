FROM python:3.12-slim

WORKDIR /app

# Copy frozen spec bundle into image (single source of truth).
COPY specs /specs

COPY src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app

ENV AURA_SPECS_DIR=/specs

ENTRYPOINT ["python", "/app/main.py"]

