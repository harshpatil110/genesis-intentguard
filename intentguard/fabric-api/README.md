# IntentGuard — Hyperledger Fabric 2.5.16 FastAPI Gateway Service

Standalone Python microservice bridging IntentGuard's Windows backend to the Hyperledger Fabric 2.5.16 permissioned blockchain running inside Ubuntu WSL2 / Docker.

---

## 1. Prerequisites

- **Windows 11 / 10** with **WSL2** installed (`wsl --install -d Ubuntu`).
- **Docker Desktop** installed on Windows with **WSL2 Integration** enabled for your Ubuntu distribution.
- **Python 3.10+** installed inside Ubuntu WSL2.

---

## 2. Hyperledger Fabric Setup

Open your **Ubuntu WSL2** terminal and run:

```bash
cd ~
mkdir -p fabric-dev
cd fabric-dev
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh && chmod +x install-fabric.sh
./install-fabric.sh docker samples binary
```

---

## 3. Network Startup & Channel Creation

Navigate to the Fabric test network directory, start the network with Certificate Authorities (CA), and create the `intentguard` channel:

```bash
cd ~/fabric-dev/fabric-samples/test-network
./network.sh up createChannel -c intentguard -ca
```

---

## 4. Chaincode Deployment

Deploy the `intentguard` smart contract (JavaScript) to the `intentguard` channel with sequence 2:

```bash
cd ~/fabric-dev/fabric-samples/test-network
./network.sh deployCC \
  -ccn intentguard \
  -ccp ../intentguard-chaincode \
  -ccl javascript \
  -ccv 1.0.1 \
  -ccs 2
```

---

## 5. API Configuration

Fabric generates the cryptographic identity materials inside the test network's organizations directory.
Create `./intentguard/fabric-api/.env` pointing to your exact WSL2 path:

```env
FABRIC_MSP_ID=Org1MSP
FABRIC_PEER_ENDPOINT=localhost:7051
FABRIC_PEER_HOST_ALIAS=peer0.org1.example.com
FABRIC_CHANNEL_NAME=intentguard
FABRIC_CHAINCODE_NAME=intentguard
FABRIC_CRYPTO_PATH=/home/<YOUR_WSL_USERNAME>/fabric-dev/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com
FABRIC_API_KEY=intentguard_local_dev_key
```

---

## 6. Running the Gateway Service

Inside your WSL2 terminal, install dependencies and start the Uvicorn server on port 8200:

```bash
cd ~/genesis-intentguard/intentguard/fabric-api
python3 -m pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8200
```

The gateway listens on `0.0.0.0:8200`, exposing:
- `POST /audit-events`: Records 12-field immutable audit events.
- `GET /audit-events/{event_id}`: Retrieves event by ID.
- `GET /audit-events`: RBAC-filtered ledger list (`Buyer`, `Supplier`, `Auditor`).

---

## 7. Main Application Connection

In the main Windows backend (`./intentguard/backend/.env`), point the blockchain client to the WSL2 service:

```env
BLOCKCHAIN_USE_MOCK=false
BLOCKCHAIN_API_BASE_URL=http://127.0.0.1:8200
```

When running in mock mode for local testing without WSL2 running:
```env
BLOCKCHAIN_USE_MOCK=true
```
