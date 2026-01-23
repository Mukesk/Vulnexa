#!/bin/bash
# Install dependencies if needed
python3 -m pip install -r backend/requirements.txt

# Run the server
echo "🚀 Starting Vulnexa Backend on http://localhost:8000"
python3 -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
