FROM python:3.14.5-alpine

RUN rm -rf /sando
RUN rm -rf pyproject.toml
# Install system and build dependencies
RUN apk update && apk add --no-cache \
    git \
    supervisor \
    nmap \
    build-base \
    libffi-dev \
    openssl-dev \
    ca-certificates


# Clone the repository (disable cache by adding a build arg that always changes)
ARG CACHEBUST=1
RUN git clone https://github.com/mayberryjp/sando.git /sando

# Set the working directory
WORKDIR /sando


# Install project in editable mode (installs dependencies from pyproject.toml)
RUN pip install --no-cache-dir .

# Expose the required ports
EXPOSE 2055
EXPOSE 8044
EXPOSE 53
EXPOSE 67
EXPOSE 8030

# Ensure Python output is not buffered
ENV PYTHONUNBUFFERED=1

# Run supervisord
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/sando/src/super.conf"]
CMD ["-n"]
