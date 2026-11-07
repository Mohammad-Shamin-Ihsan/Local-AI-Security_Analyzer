"""
FastAPI application entry point.
Provides REST API for log analysis.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import psutil
from pathlib import Path

from src.config import Config
from src.models.database import Database
from src.services.ollama_client import OllamaClient
from src.api.routes import upload, analysis
from src.utils.tokenizer import token_counter


# Global instances
db: Database | None = None
ollama: OllamaClient | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Startup and shutdown events."""
    global db, ollama

    # Startup
    print("Initializing application...")

    # Initialize database
    db = Database(Config.DATABASE_PATH)
    await db.initialize()
    print(f"Database initialized at {Config.DATABASE_PATH}")

    # Initialize Ollama client
    ollama = OllamaClient()
    if await ollama.test_connection():
        print(f"Connected to Ollama at {Config.OLLAMA_HOST}")
        print(f"Using model: {Config.OLLAMA_MODEL}")
    else:
        print("Ollama/model unavailable. Start Ollama and install the model with:")
        print(f"ollama pull {Config.OLLAMA_MODEL}")

    # Log memory usage
    memory = psutil.Process().memory_info().rss / (1024 * 1024)
    print(f"Application memory: {memory:.1f} MB")
    print(f"Tokenizer mode: {token_counter.mode}")

    # Set global instances for analysis routes
    set_analysis_globals(db, ollama)

    yield

    # Shutdown
    await ollama.close()
    print("Application shutdown complete")


app = FastAPI(
    title="Local AI Security Log Analyzer",
    description="Analyze server logs for security threats using local LLM",
    version="1.0.0",
    lifespan=lifespan
)

# Register routers
app.include_router(upload.router)
app.include_router(analysis.router)


# Set global instances for analysis routes (called in lifespan)
def set_analysis_globals(db, ollama):
    """Set global db and ollama instances for analysis routes."""
    from src.api.routes.analysis import set_global_instances
    set_global_instances(db, ollama)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "running",
        "model": Config.OLLAMA_MODEL,
        "max_context_tokens": Config.MAX_CONTEXT_TOKENS,
        "tokenizer_mode": token_counter.mode,
    }


@app.get("/health")
async def health():
    """Detailed health check."""
    # Check Ollama connection
    ollama_status = await ollama.test_connection() if ollama else False

    # Get memory info
    process = psutil.Process()
    memory_mb = process.memory_info().rss / (1024 * 1024)
    system_memory = psutil.virtual_memory()

    return {
        "status": "healthy" if ollama_status else "degraded",
        "ollama_connected": ollama_status,
        "model": Config.OLLAMA_MODEL,
        "tokenizer_mode": token_counter.mode,
        "context_tokens": Config.MAX_CONTEXT_TOKENS,
        "memory": {
            "process_mb": round(memory_mb, 1),
            "system_available_mb": round(system_memory.available / (1024 * 1024), 1),
            "system_percent": system_memory.percent
        }
    }


@app.get("/dashboard")
async def dashboard():
    """Serve the dashboard HTML."""
    dashboard_path = Path(__file__).resolve().parents[2] / "public" / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())
    return {"error": "Dashboard not found"}


# Mount static files directory
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parents[2] / "public"),
    name="static"
)
