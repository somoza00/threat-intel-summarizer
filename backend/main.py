from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from routers import analyze, news

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Threat Intel Summarizer",
    description="Analisa IPs, hashes, domínios e CVEs usando múltiplas APIs",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://threat-intel-summarizer-production-b2f7.up.railway.app",
        "https://threat-intel-summarizer-eta.vercel.app",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api")
app.include_router(news.router, prefix="/api")


@app.get("/")
def root():
    return {"status": "ok", "message": "Threat Intel Summarizer API"}