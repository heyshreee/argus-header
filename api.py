
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Import internal modules
from argus_header.requester import fetch_headers
from argus_header.analyzer import analyze_headers
from argus_header.schemas import AnalyzeRequest


# Create FastAPI app
app = FastAPI(
    title="HTTP Header Analyzer API",
    description="An API to fetch and analyze HTTP headers for security issues.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # frontend access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/analyze", summary="Fetch and analyze HTTP headers from a URL")
def analyze_url(url: str):
    start = time.perf_counter()
    response_data = fetch_headers(url)
    
    if not response_data.get("success"):
        raise HTTPException(
            status_code=400,
            detail=response_data.get("error", "Failed to fetch headers.")
        )
    
    findings = analyze_headers(response_data)
    
        
    end = time.perf_counter()
    backend_time =  get_backend_time(start, end)
    
    return {
        "url": response_data.get("url"),
        "status": response_data.get("status_code"),
        "headers": response_data.get("headers"),
        "analysis": findings  ,
        "timing": {
            "backend_seconds": backend_time
        }
    }
    

@app.post("/analyze", summary="Fetch and analyze HTTP headers from a URL (POST)")
def analyze_url_post(payload: AnalyzeRequest):
    
    start = time.perf_counter()
    
    response_data = fetch_headers(str(payload.url))
    
    if not response_data.get("success"):
        raise HTTPException(
            status_code=400,
            detail=response_data.get("error", "Failed to fetch headers.")
        )
    
    findings = analyze_headers(response_data)
    
    end = time.perf_counter()
    backend_time =  get_backend_time(start, end)
    
    return {
        "response" : response_data,
        "analysis": findings,
        "timing": {
            "backend_seconds": backend_time
        }
    }



def get_backend_time(start_time: float, end_time: float) -> float:
    """Calculate backend processing time in seconds."""
    return round(end_time - start_time, 4)