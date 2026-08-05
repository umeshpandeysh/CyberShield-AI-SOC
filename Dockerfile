FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for YARA & ClamAV
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libyara-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY backend /app/backend
COPY . .

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
