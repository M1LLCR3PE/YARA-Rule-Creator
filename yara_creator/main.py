"""YARA Rule Creator - Main Entry Point"""

import threading
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api.routes import templates, validation, extraction, testing

# Create FastAPI app
app = FastAPI(
    title="YARA Rule Creator",
    description="Desktop application for creating and testing YARA rules",
    version="1.0.0"
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")

# Setup templates
templates_jinja = Jinja2Templates(directory=str(config.TEMPLATES_DIR))

# Include API routers
app.include_router(templates.router)
app.include_router(validation.router)
app.include_router(extraction.router)
app.include_router(testing.router)


@app.get("/")
async def index(request: Request):
    """Serve the main application page"""
    return templates_jinja.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


def run_server():
    """Run the FastAPI server"""
    uvicorn.run(
        app,
        host=config.HOST,
        port=config.PORT,
        log_level="warning" if not config.DEBUG else "info"
    )


def start_desktop():
    """Start the application as a desktop window using PyWebView"""
    try:
        import webview
        WEBVIEW_AVAILABLE = True
    except ImportError:
        WEBVIEW_AVAILABLE = False

    # Start server in a separate thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for server to start
    import time
    import urllib.request
    for _ in range(50):  # Wait up to 5 seconds
        try:
            urllib.request.urlopen(f"http://{config.HOST}:{config.PORT}/health")
            break
        except Exception:
            time.sleep(0.1)

    url = f"http://{config.HOST}:{config.PORT}"

    if WEBVIEW_AVAILABLE:
        # Create desktop window
        window = webview.create_window(
            title="YARA Rule Creator",
            url=url,
            width=1400,
            height=900,
            min_size=(1000, 700),
            resizable=True
        )
        # Start webview
        webview.start(debug=config.DEBUG)
    else:
        # Open in default browser
        import webbrowser
        print(f"Opening YARA Rule Creator in browser: {url}")
        webbrowser.open(url)
        # Keep server running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    import sys

    if "--server" in sys.argv:
        # Run as web server only
        run_server()
    else:
        # Run as desktop application
        start_desktop()
