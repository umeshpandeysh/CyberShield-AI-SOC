from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.adapters.routes.auth import router as auth_router
from app.adapters.routes.ingest import router as ingest_router
from app.adapters.routes.alerts import router as alerts_router
from app.adapters.routes.tasks import router as tasks_router
from app.adapters.routes.cases import router as cases_router
from app.adapters.routes.threat_intel import router as threat_intel_router
from app.adapters.routes.metrics import router as metrics_router
from app.adapters.routes.websockets import router as websockets_router
from app.adapters.routes.reports import router as reports_router
from app.adapters.routes.admin import router as admin_router
from app.adapters.routes.settings_route import router as settings_router

app = FastAPI(
    title="CyberShield-AI-SOC API",
    description="Production-grade threat detection dashboard API backend.",
    version="0.1.0-alpha"
)

# Enable CORS for frontend dashboard interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(auth_router)
app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(tasks_router)
app.include_router(cases_router)
app.include_router(threat_intel_router)
app.include_router(metrics_router)
app.include_router(websockets_router)
app.include_router(reports_router)
app.include_router(admin_router)
app.include_router(settings_router)

@app.get("/health", tags=["Health Check"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "backend",
        "timestamp": "2026-08-01T22:29:07+05:30"
    }
