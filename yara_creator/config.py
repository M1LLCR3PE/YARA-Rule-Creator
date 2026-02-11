"""Application configuration"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR / "frontend"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"
CORE_TEMPLATES_DIR = BASE_DIR / "core" / "templates"

# Server settings
HOST = "127.0.0.1"
PORT = 8765
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# File upload settings
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".exe", ".dll", ".bin", ".dat", ".yar", ".yara"}

# String extraction settings
MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 256
