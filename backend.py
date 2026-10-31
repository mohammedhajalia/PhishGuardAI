from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from detector import analyze_message, analyze_url

app = FastAPI(
    title="PhishGuard AI",
    description="Phishing Detection and Investigation Platform",
    version="1.0.0"
)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)
# Development CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# Request models
class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20000)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


# Home endpoint
@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


# Health endpoint
@app.get("/health")
def health():
    return {
        "status": "Healthy"
    }


# Message analysis endpoint
@app.post("/analyze-message")
def message_analysis(request: MessageRequest):

    score, risk, findings, urls = analyze_message(
        request.message
    )

    return {
        "type": "Message Analysis",
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "detected_urls": urls
    }


# URL analysis endpoint
@app.post("/analyze-url")
def url_analysis(request: URLRequest):

    score, risk, findings = analyze_url(
        request.url
    )

    return {
        "type": "URL Investigation",
        "url": request.url,
        "risk_score": score,
        "risk_level": risk,
        "findings": findings
    }
