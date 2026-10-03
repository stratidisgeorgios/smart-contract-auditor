"""
FastAPI entry point. 
This is the file that boots the whole backend. It creates the FastAPI app,
configures logging, adds middleware, and registers the API routes.
To Run it locally:  uvicorn main:app --reload --port 8000
On Render: automatically via Dockerfile CMD
"""

import logging
import sys
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv() # Load backend/.env before importing modules that read env vars (no-op on Render, where vars are set directly)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router # Import the router defined in api/routes.py, which contians all our API endpoints

logging.basicConfig( # Configure the global logger that every module in the project will share.
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan handler: code that runs once when the server starts and once when it stops.
    Everything before yield runs at startup and everything after yield runs at shutdown.
    
    Internal note: Right now we just log messages, but this is the place to add things like
    database connection, caches, etc. 
    """
    logger.info("Smart Contract Audit Backend starting…")
    yield
    logger.info("Backend shutting down.")


# Create the main FastAPI application instance.
app = FastAPI(
    title="Smart Contract Audit API",
    description="LLM + Slither security auditing pipeline for Solidity contracts.",
    version="1.0.0",
    lifespan=lifespan,  #attach our startup/shutdown handler
)

# Addition of CORS middleware
# Browsers block requests from one domain to another by default for security reasons.
# This middleware adds the HTTP headers so our frontend (on a different domain) is allowed to call our API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # TODO tight to frontend URL in production (for dev is okey as it is)
    allow_methods=["*"], # allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"], # allow all request headers
)

app.include_router(router) # This makes all the endpoints defined available on our app

if __name__ == "__main__": #for development purposes. Only runs if python main.py is executed.
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
