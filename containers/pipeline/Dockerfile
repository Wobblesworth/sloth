FROM python:3.12-slim

# Versions
ARG HAYABUSA_VERSION=3.8.1

# Install system dependencies (incl. build tools for libscca-python)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        unzip \
        ca-certificates \
        build-essential \
        python3-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Hayabusa
RUN curl -L -o /tmp/hayabusa.zip \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" && \
    unzip /tmp/hayabusa.zip -d /opt/hayabusa && \
    chmod +x /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu && \
    ln -s /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu /usr/local/bin/hayabusa && \
    rm /tmp/hayabusa.zip

# Install Python dependencies (libscca is the Prefetch parser)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy pipeline code
COPY . .

# Tool binary locations
ENV HAYABUSA_BIN=/usr/local/bin/hayabusa

CMD ["python3", "watcher.py"]
