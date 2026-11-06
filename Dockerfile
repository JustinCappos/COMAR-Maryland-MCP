FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data comar
COPY --from=build /src/target/release/comar-mcp /usr/local/bin/comar-mcp
USER comar
VOLUME /data
ENV COMAR_MCP_DATA_DIR=/data \
    COMAR_MCP_TRANSPORT=http \
    COMAR_MCP_BIND=0.0.0.0:8000
EXPOSE 8000
HEALTHCHECK CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8000"]
ENTRYPOINT ["comar-mcp"]
