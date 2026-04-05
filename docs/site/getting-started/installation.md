# Installation

## SDK Installation

The AgentPEP Python SDK is available on PyPI:

```bash
# Core SDK
pip install agentpep-sdk

# With LangChain integration
pip install agentpep-sdk[langchain]

# With FastAPI middleware
pip install agentpep-sdk[fastapi]

# All extras
pip install agentpep-sdk[langchain,fastapi]
```

### Requirements

- Python 3.11 or later
- `httpx` >= 0.27.0
- `pydantic` >= 2.10.0

## Server Installation

### Docker Compose (Recommended)

```bash
git clone https://github.com/Shivapas/agentpep.git
cd agentpep
docker compose up -d
```

Services:

| Service | Port | Description |
|---------|------|-------------|
| Backend | 8000 | FastAPI authorization engine |
| Frontend | 5173 | Policy Console (React) |
| MongoDB | 27017 | Policy and audit storage |
| Kafka | 9092 | Event streaming (optional) |

### Manual Installation

```bash
# Backend
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

### Kubernetes (Helm)

```bash
cd infra/helm
helm install agentpep ./agentpep \
  --set tenant.id=my-tenant \
  --set mongodb.url=mongodb://mongodb:27017 \
  --set backend.image.tag=latest
```

See [Deployment Guide](../guides/deployment.md) for production deployment options.

## Configuration

The backend is configured via environment variables prefixed with `AGENTPEP_`:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPEP_MONGODB_URL` | `mongodb://localhost:27017` | MongoDB connection string |
| `AGENTPEP_MONGODB_DB_NAME` | `agentpep` | Database name |
| `AGENTPEP_DEBUG` | `false` | Enable debug mode |
| `AGENTPEP_AUTH_ENABLED` | `false` | Require API key authentication |
| `AGENTPEP_MTLS_ENABLED` | `false` | Require mTLS client certificates |
| `AGENTPEP_DEFAULT_FAIL_MODE` | `FAIL_CLOSED` | Behavior on timeout: FAIL_OPEN or FAIL_CLOSED |
| `AGENTPEP_EVALUATION_TIMEOUT_S` | `5.0` | Policy evaluation timeout (seconds) |
| `AGENTPEP_OTLP_ENDPOINT` | `http://localhost:4317` | OpenTelemetry collector endpoint |
| `AGENTPEP_CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed CORS origins |
| `AGENTPEP_GRPC_ENABLED` | `false` | Enable gRPC server |
| `AGENTPEP_GRPC_PORT` | `50051` | gRPC server port |
