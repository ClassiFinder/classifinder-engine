FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/

EXPOSE 8000

ENV CLASSIFINDER_API_KEYS=""
ENV CLASSIFINDER_RATE_LIMIT_PER_MINUTE="60"
ENV CLASSIFINDER_MAX_PAYLOAD_BYTES="262144"
ENV CLASSIFINDER_VERSION="1.0.0"

RUN adduser --disabled-password --no-create-home appuser
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
