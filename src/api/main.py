from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import asyncio
from datetime import datetime
import json

from src.api.routes import alerts, dashboard, reports, events
from src.detection.realtime_detector import RealtimeDetector
from src.alerting.email_notifier import EmailNotifier
from src.data.elasticsearch_client import ElasticsearchClient

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.detector = RealtimeDetector()
    app.state.email_notifier = EmailNotifier()
    app.state.es_client = ElasticsearchClient()
    
    # Start detection engine
    asyncio.create_task(app.state.detector.start())
    
    yield
    
    # Shutdown
    await app.state.detector.stop()

app = FastAPI(title="Insider Threat Detection API", 
              version="1.0.0",
              lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(events.router, prefix="/api/v1/events", tags=["events"])

# WebSocket for real-time updates
@app.websocket("/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Send real-time threat data
            threats = app.state.detector.get_recent_threats()
            await websocket.send_json({
                "type": "threat_update",
                "timestamp": datetime.now().isoformat(),
                "data": threats
            })
            await asyncio.sleep(2)  # Update every 2 seconds
    except WebSocketDisconnect:
        print("Client disconnected")

@app.get("/")
async def root():
    return {"message": "Insider Threat Detection API", "status": "operational"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "elasticsearch": await app.state.es_client.check_health(),
            "detector": app.state.detector.is_running(),
            "email_service": app.state.email_notifier.is_connected()
        }
    }