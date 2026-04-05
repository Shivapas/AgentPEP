# Health Endpoints

## GET /health

Liveness probe. Returns immediately without checking dependencies.

```json
{"status": "ok", "version": "0.1.0"}
```

## GET /ready

Readiness probe. Checks MongoDB connectivity.

```json
{"status": "ok", "mongodb": "connected"}
```

If MongoDB is unavailable:

```json
{"status": "degraded", "mongodb": "unavailable"}
```
