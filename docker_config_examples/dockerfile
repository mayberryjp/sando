FROM python:3.13.3-alpine

# Install system and build dependencies
RUN apk update && apk add --no-cache \
    git \
    supervisor \
    nmap \
    build-base \
    libffi-dev \
    openssl-dev \
    ca-certificates

# Clone the repository
RUN git clone https://github.com/mayberryjp/sando.git /sando

# Set the working directory
WORKDIR /sando

# Install Python dependencies
RUN pip install --no-cache-dir schedule requests bottle dnspython python-nmap psutil dnslib waitress pytz

# Expose the required ports
EXPOSE 2055
EXPOSE 8044
EXPOSE 53
EXPOSE 67

# Ensure Python output is not buffered
ENV PYTHONUNBUFFERED=1

# Run supervisord
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/sando/super.conf"]
CMD ["-n"]
