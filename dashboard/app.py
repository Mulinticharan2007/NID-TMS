from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database.database_manager import get_alerts

app = FastAPI(title="NID-TMS Dashboard")

BASE_DIR = Path(__file__).resolve().parent


@app.get("/")
def dashboard():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/alerts")
def alerts():
    return {"alerts": get_alerts()}


@app.get("/health")
def health():
    return {"status": "NID-TMS dashboard is running"}