# Build stage
FROM docker.io/library/rust:slim AS builder

RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ../. .
RUN cargo build -p once-mtls-server --release

# Deployment
FROM docker.io/library/debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpq5 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/once-mtls-server /usr/local/bin/servidor-autenticacion-dnie

WORKDIR /dnie-certs
ADD http://pki.policia.es/dnie/certs/AC004.crt AC004.der
ADD http://pki.policia.es/dnie/certs/AC005.crt AC005.der
ADD http://pki.policia.es/dnie/certs/AC006.crt AC006.der
ADD http://pki.policia.es/dnie/certs/ACRaiz2.crt ACRaiz2.der

ENV DNIE_CERTS_DIR="/dnie-certs"

WORKDIR /app

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/servidor-autenticacion-dnie"]
