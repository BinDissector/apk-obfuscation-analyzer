# APK Obfuscation Analyzer Docker Image
# Provides a consistent environment with all dependencies

FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /analyzer

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    unzip \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install jadx
RUN JADX_VERSION=1.4.7 && \
    wget -q https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip && \
    unzip -q jadx-${JADX_VERSION}.zip -d /opt/jadx && \
    rm jadx-${JADX_VERSION}.zip && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    chmod +x /opt/jadx/bin/jadx

# Verify jadx installation
RUN jadx --version

# Copy analyzer files
COPY analyzer.py /analyzer/
COPY test_obfuscation.py /analyzer/
COPY requirements.txt /analyzer/
COPY batch_analyze.sh /analyzer/

# Make scripts executable
RUN chmod +x /analyzer/*.py /analyzer/*.sh

# Create directories for APKs and results
RUN mkdir -p /apks /results

# Set Python to run in unbuffered mode (better for logging)
ENV PYTHONUNBUFFERED=1

# Default command: show help
ENTRYPOINT ["python3", "/analyzer/analyzer.py"]
CMD ["--help"]

# Usage examples:
#
# Build:
#   docker build -t apk-analyzer .
#
# Run analysis:
#   docker run -v $(pwd)/apks:/apks -v $(pwd)/results:/results apk-analyzer \
#       /apks/original.apk /apks/obfuscated.apk -o /results
#
# Run tests:
#   docker run apk-analyzer python3 /analyzer/test_obfuscation.py
#
# Interactive shell:
#   docker run -it --entrypoint /bin/bash apk-analyzer
#
# Batch processing:
#   docker run -v $(pwd)/apks:/apks -v $(pwd)/results:/results \
#       --entrypoint /analyzer/batch_analyze.sh apk-analyzer \
#       -d /apks -o /results
