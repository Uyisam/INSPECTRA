from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database.connection import engine, Base

from backend.models.project import Project
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.finding import Finding
from backend.models.remediation import RemediationTask
from backend.models.notification import Notification

# API routers
from backend.api.projects import router as projects_router
from backend.api.assets import router as assets_router
from backend.api.scans import router as scans_router
from backend.api.findings import router as findings_router
from backend.api.remediation import router as remediation_router
from backend.api.notifications import router as notifications_router


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Inspectra",
    description="Automated Vulnerability Management & Risk Intelligence Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects_router)
app.include_router(assets_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(remediation_router)
app.include_router(notifications_router)


# Root endpoint
@app.get("/")
def home():
    return {
        "message": "Welcome to Inspectra",
        "status": "running"
    }