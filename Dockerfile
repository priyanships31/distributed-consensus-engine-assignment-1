# =============================================================================
#  Dockerfile
#
#  Single image used by every service in docker-compose.yml:
#    node1–node5  →  python node.py       (honest consensus nodes)
#    node6        →  python adversary.py  (Byzantine adversary)
#    client       →  python client.py     (transaction generator)
#
#  Python 3.14 compatible.
#  Excluded: grpcio (broken on 3.14), uvloop (no 3.14 wheel).
#  All networking is pure asyncio (stdlib).
#
#  Required project layout (assignment spec):
#    distributed-consensus-engine/
#    ├── src/
#    │   ├── node.py
#    │   ├── adversary.py
#    │   ├── client.py
#    │   └── crypto_utils.py
#    ├── tests/
#    │   └── chaos_test.sh
#    ├── data/
#    ├── keys/
#    ├── Dockerfile
#    ├── docker-compose.yml
#    └── requirements.txt
#
#  Build:
#    docker build -t consensus-engine:latest .
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 – dependency builder
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
        cargo \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip

# Prefer binary wheel; fall back to source compile if none available
RUN pip wheel --no-cache-dir --prefer-binary \
        --wheel-dir /wheels \
        cryptography requests pytest pytest-asyncio \
 || ( echo "[builder] Falling back to source compile" \
      && pip wheel --no-cache-dir \
              --wheel-dir /wheels \
              cryptography requests pytest pytest-asyncio )

# ---------------------------------------------------------------------------
# Stage 2 – runtime image
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS runtime

LABEL maintainer="IIT Jodhpur – Distributed Systems Assignment-1"
LABEL description="Distributed consensus engine: Paxos + PBFT (Python 3.14)"

RUN apt-get update && apt-get install -y --no-install-recommends \
        netcat-openbsd \
        curl \
        jq \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        cryptography requests \
 && rm -rf /wheels

# ---------------------------------------------------------------------------
# Application source — copied from src/ (assignment folder structure)
# ---------------------------------------------------------------------------
WORKDIR /app

COPY src/node.py         ./node.py
COPY src/adversary.py    ./adversary.py
COPY src/client.py       ./client.py
COPY src/crypto_utils.py ./crypto_utils.py

# Copy tests so chaos_test.sh is available inside the client container
COPY tests/chaos_test.sh ./tests/chaos_test.sh

# ---------------------------------------------------------------------------
# Runtime directories — bind-mounted by docker-compose at runtime
# ---------------------------------------------------------------------------
RUN mkdir -p /data /keys /app/tests \
 && chmod +x /app/tests/chaos_test.sh

# ---------------------------------------------------------------------------
# Environment defaults
# ---------------------------------------------------------------------------
ENV NODE_ID=1 \
    NODE_HOST=0.0.0.0 \
    NODE_PORT=5001 \
    MODE=B \
    PEERS="" \
    KEY_DIR=/keys \
    CLUSTER_HMAC_SECRET=iitj-ds-change-in-production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5001 5101

CMD ["python", "node.py", \
     "--id",   "1", \
     "--port", "5001", \
     "--peers", "", \
     "--mode", "B"]