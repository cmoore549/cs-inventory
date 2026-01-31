FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create upload directories
RUN mkdir -p static/uploads/logo instance

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default port (Railway sets PORT env var)
ENV PORT=8080
EXPOSE 8080

# Run the application
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT} --workers 2"]
