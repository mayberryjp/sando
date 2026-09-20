# Builder stage: only needs git to clone the repo, kept out of the final image
FROM python:3.14.5-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone the repository (disable cache by adding a build arg that always changes)
ARG CACHEBUST=1
RUN git clone https://github.com/mayberryjp/sando.git /sando


# Final stage
FROM python:3.14.5-slim

# Bring in the cloned source from the builder stage
COPY --from=builder /sando /sando

# Set the working directory
WORKDIR /sando

# Install supervisor (via pip, reusing the existing interpreter) and the project
RUN pip install --no-cache-dir supervisor .

# Expose the required ports
EXPOSE 2055
EXPOSE 8044
EXPOSE 53
EXPOSE 67
EXPOSE 8030

# Ensure Python output is not buffered
ENV PYTHONUNBUFFERED=1

# Run supervisord
ENTRYPOINT ["/usr/local/bin/supervisord", "-c", "/sando/src/super.conf"]
CMD ["-n"]
