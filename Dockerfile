# Use a small version of python
FROM python:3.11-slim

LABEL maintainer="Christopher Fennell"
LABEL description="Self-hosted Active Directory management web interface"
LABEL license="MIT"

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app code
COPY . .

# Create data directory for audit log SQLite database
RUN mkdir -p /app/data

# Enable legacy OpenSSL providers (MD4 needed for NTLM auth)
# Use our minimal config that activates legacy provider
ENV OPENSSL_CONF=/app/openssl_legacy.cnf

# Expose the internal port (Gunicorn default)
EXPOSE 8000

# Run with Gunicorn (Production web server for Python)
# 4 workers handles multiple requests nicely
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
