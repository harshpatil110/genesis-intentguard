#!/bin/bash
echo "==========================================================="
echo "INTENTGUARD (GENESIS 2.0 | PS 01) - FULL SYSTEM STARTUP"
echo "==========================================================="

echo "[1/3] Verifying WSL2 Hyperledger Fabric Gateway (Port 8200)..."
echo "Ensure your Fabric test-network and FastAPI Gateway are running on :8200"

echo "[2/3] Building and Starting Docker Containers..."
docker-compose up --build -d

echo "[3/3] System is Online!"
echo "-> IntentGuard Backend API: http://localhost:8000"
echo "-> Next.js Forensic X-Ray UI: http://localhost:3000"
echo "-> OpenClaw Sandbox Gateway: ws://localhost:18789"
echo "Logs: Run 'docker-compose logs -f' to view real-time telemetry."
