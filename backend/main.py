from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import analyze

app = FastAPI(
    title="Threat Intel Summarizer",
    description="Analisa IPs, hashes, domínios e CVEs usando múltiplas APIs + AI",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api")


@app.get("/")
def root():
    return {"status": "ok", "message": "Threat Intel Summarizer API"}