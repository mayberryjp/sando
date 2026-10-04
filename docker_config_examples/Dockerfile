# Builder stage: clone the repo and build deps. The toolchain (needed to compile
# psutil's C extension against musl) and git stay out of the final image.
FROM python:3.14.5-alpine AS builder

RUN apk add --no-cache git gcc musl-dev linux-headers

# Shallow clone keeps the builder lean (disable cache via an always-changing arg)
ARG CACHEBUST=1
RUN git clone --depth 1 https://github.com/mayberryjp/sando.git /sando

# Install supervisor + the project into an isolated prefix we can copy wholesale,
# then drop the git history (never needed at runtime)
RUN pip install --no-cache-dir --prefix=/install supervisor /sando \
    && rm -rf /sando/.git

# Final stage: runtime only — no toolchain, no git, no history
FROM python:3.14.5-alpine

# Bring in the compiled packages/binaries and the .git-free source
COPY --from=builder /install /usr/local
COPY --from=builder /sando /sando

# Set the working directory
WORKDIR /sando

# Expose the required ports
EXPOSE 2055 8044 53 67 8030

# Ensure Python output is not buffered
ENV PYTHONUNBUFFERED=1

# Run supervisord
ENTRYPOINT ["/usr/local/bin/supervisord", "-c", "/sando/src/super.conf"]
CMD ["-n"]
