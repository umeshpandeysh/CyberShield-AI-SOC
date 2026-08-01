from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.adapters.routes.auth import router as auth_router
from app.adapters.routes.ingest import router as ingest_router
from app.adapters.routes.alerts import router as alerts_router

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

@app.get("/health", tags=["Health Check"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "backend",
        "timestamp": "2026-08-01T22:29:07+05:30"
    }
