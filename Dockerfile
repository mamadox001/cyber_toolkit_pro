# =============================================================================
# CyberToolkit Pro — Docker Support
# =============================================================================
FROM python:3.11-slim

LABEL maintainer="CyberToolkit Pro Team"
LABEL description="Professional Cybersecurity Framework"
LABEL version="2.0.0"

# Install system tools commonly needed for security testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cybertoolkit

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir fastapi uvicorn dnspython

# Copy framework
COPY . .

# Create required directories
RUN mkdir -p logs reports

# Expose dashboard port
EXPOSE 8443

# Default: interactive mode
ENTRYPOINT ["python", "main.py"]
CMD ["--interactive"]
