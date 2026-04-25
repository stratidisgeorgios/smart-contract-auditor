"""
HTTP endpoints.
This file defines the two URLs of the API:
  POST /api/v1/audit  —> receives a Solidity file and returns the audit report
  GET  /api/v1/health —> liveness check used by Render and monitoring tools
"""

import logging
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from pipeline.graph import run_audit #main pipeline function that orchestrates the whole audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["audit"]) # APIRouter groups related endpoints together and prefixes every URL with /api/v1.

MAX_FILE_SIZE = 500_000  # we reject files larger than 500 KB to keep LLM token usage reasonable, as the free tier of Groq has strict token limits.


@router.post("/audit", summary="Audit a Solidity smart contract")
async def audit_contract(file: UploadFile = File(...)):
    """
    Main endpoint. Accepts a .sol file upload and returns a JSON audit report.
    """
    filename = file.filename or "contract.sol" # Use the original filename or fall back to a default if none was provided

    if not filename.endswith(".sol"): # Reject anything that isn't a Solidity file based on the file extension
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .sol (Solidity) files are accepted.",
        )

    content_bytes = await file.read()

    if not content_bytes: # Reject empty files: nothing to audit
        raise HTTPException(status_code=422, detail="File is empty.")

    if len(content_bytes) > MAX_FILE_SIZE: # Reject files that are too large
        raise HTTPException(status_code=413, detail="File exceeds 500 KB limit.")

    # Try to decode the bytes as UTF-8 text. Solidity source files must be text. Binary files would fail.
    try:
        contract_code = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="File must be UTF-8 encoded.")

    logger.info("Received: %s (%d bytes)", filename, len(content_bytes)) # Log a brief summary of the received file for debugging purposes

    try:  # Send to the audit pipeline and wait for the result. Any unexpected exception is caught and returned as a 500 error.
        report = await run_audit(contract_code=contract_code, contract_name=filename)
    except Exception as exc:
        logger.exception("Pipeline error")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}")

    return JSONResponse(content=report) # Return the report dict as a JSON response


@router.get("/health", summary="Health check")
async def health():
    """
    Simple endpoint. Returns {"status": "ok"} when the server is up. This is used by Render's health check and any external monitoring. It's useful to have it
    """
    return {"status": "ok"}
