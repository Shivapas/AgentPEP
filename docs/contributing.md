# Contributing to AgentPEP

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker & Docker Compose

### Local Development

```bash
# Start infrastructure
docker compose up mongodb kafka zookeeper -d

# Backend
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# SDK
cd sdk
pip install -e ".[dev]"
```

### Running Tests

```bash
# Backend
cd backend && pytest -v

# SDK
cd sdk && pytest -v

# Frontend
cd frontend && npm run lint && npm run typecheck
```

## Code Style

- **Python**: Ruff for linting and formatting, mypy for type checking
- **TypeScript**: ESLint + TypeScript strict mode
- **Commits**: Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)

## Pull Request Process

1. Create a feature branch from `main`
2. Implement changes with tests
3. Ensure CI passes (lint, type-check, test, build)
4. Request review from at least one maintainer

## Architecture Decision Records

For significant architectural decisions, create an ADR in `docs/adr/` using the template at `docs/adr/TEMPLATE.md`.
