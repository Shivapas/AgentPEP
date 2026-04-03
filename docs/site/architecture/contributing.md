# Contributing to AgentPEP

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker and Docker Compose

### Backend

```bash
cd backend
pip install -e ".[dev]"
pytest -v                  # Run tests
ruff check .               # Lint
ruff format --check .      # Format check
mypy app --ignore-missing-imports  # Type check
```

### SDK

```bash
cd sdk
pip install -e ".[dev]"
pytest -v
ruff check .
mypy agentpep --ignore-missing-imports
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # Dev server on :5173
npm run lint         # ESLint
npm run typecheck    # TypeScript check
npm run build        # Production build
```

## Code Style

- **Python**: Ruff for linting/formatting, mypy for type checking
- **TypeScript**: ESLint, strict TypeScript
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/)

## Pull Request Process

1. Create a feature branch from `main`
2. Make changes with tests
3. Ensure CI passes (lint, typecheck, test)
4. Submit PR with description of changes
5. Get review and address feedback
