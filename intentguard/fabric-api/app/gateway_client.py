"""Hyperledger Fabric 2.5.16 Gateway Client Connector.

Establishes a gRPC connection to peer0.org1.example.com using the Fabric Gateway SDK,
submits transactions to the ordering service, and evaluates chaincode queries.
"""

from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import grpc
import grpc.aio

from app.config import FabricSettings, get_fabric_settings

logger = logging.getLogger("intentguard.fabric_api.gateway_client")

try:
    from fabric_gateway import Gateway
    from fabric_gateway.pkg.identity import identity, signer
except ImportError:
    try:
        from moe_fabric_gateway import Gateway
        from moe_fabric_gateway.pkg.identity import identity, signer
    except ImportError:  # pragma: no cover
        class Gateway:  # type: ignore
            """Fallback Gateway stub when SDK is not installed."""
            def __init__(self, *args, **kwargs):
                pass

            def get_network(self, name: str):
                pass

            def close(self):
                pass

        identity = None
        signer = None


class _AwaitableNone:
    """Helper enabling a synchronous method return value to also be awaited."""

    def __await__(self):
        async def _dummy():
            return None
        return _dummy().__await__()


def read_file(file_path: Union[str, Path]) -> bytes:
    """Read bytes from a certificate or key PEM file.

    Raises:
        FileNotFoundError: If the target file does not exist or is not a regular file.
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    return p.read_bytes()


def read_first_file_in_dir(dir_path: Union[str, Path]) -> bytes:
    """Read the private key from the first regular file in the keystore directory.

    Raises:
        FileNotFoundError: If the directory does not exist or contains no key files.
    """
    p = Path(dir_path)
    if not p.exists() or not p.is_dir():
        raise FileNotFoundError(f"Keystore directory not found: {p}")

    files = [f for f in sorted(p.iterdir()) if f.is_file()]
    if not files:
        raise FileNotFoundError(f"No private key file found in keystore directory: {p}")
    return files[0].read_bytes()


class FabricGatewayClient:
    """High-speed gRPC connector to Hyperledger Fabric 2.5.16 Gateway."""

    def __init__(self, settings: Optional[FabricSettings] = None):
        """Initialize client with settings without establishing connection immediately (lazy)."""
        self.settings: FabricSettings = settings or get_fabric_settings()
        self.channel: Optional[grpc.aio.Channel] = None
        self.gateway: Any = None
        self.network: Any = None
        self.contract: Any = None
        self.is_connected: bool = False

    def connect(self) -> _AwaitableNone:
        """Read TLS root certs and user signing identities, establish secure gRPC channel and gateway.

        Raises:
            FileNotFoundError: If crypto materials do not exist on the file system.
        """
        tls_path = Path(self.settings.tls_cert_path)
        cert_path = Path(self.settings.cert_path)
        key_path = Path(self.settings.key_path)

        # 1. Read crypto materials; raises FileNotFoundError if missing
        tls_cert_pem = read_file(tls_path)
        client_cert_pem = read_file(cert_path)
        if key_path.is_dir():
            private_key_pem = read_first_file_in_dir(key_path)
        elif key_path.is_file():
            private_key_pem = read_file(key_path)
        else:
            raise FileNotFoundError(f"Private key path not found: {key_path}")

        # 2. Build gRPC TLS credentials and channel
        credentials = grpc.ssl_channel_credentials(root_certificates=tls_cert_pem)
        self.channel = grpc.aio.secure_channel(
            target=self.settings.FABRIC_PEER_ENDPOINT,
            credentials=credentials,
            options=(("grpc.ssl_target_name_override", self.settings.FABRIC_PEER_HOST_ALIAS),)
        )

        # 3. Instantiate Identity and Signer
        id_obj = None
        signer_obj = None

        if identity is not None and hasattr(identity, "X509Identity"):
            try:
                id_obj = identity.X509Identity(self.settings.FABRIC_MSP_ID, client_cert_pem)
            except Exception as e:
                logger.warning("Could not instantiate X509Identity: %s", e)

        if signer is not None and hasattr(signer, "load_private_key_from_pem") and hasattr(signer, "EcdsaSigner"):
            try:
                priv_key = signer.load_private_key_from_pem(private_key_pem)
                signer_obj = signer.EcdsaSigner(priv_key)
            except Exception as e:
                logger.warning("Could not instantiate EcdsaSigner: %s", e)

        # 4. Connect Gateway and bind network and contract
        try:
            self.gateway = Gateway(client=self.channel, identity=id_obj, signer=signer_obj)
        except TypeError:
            try:
                self.gateway = Gateway(self.channel, id_obj, signer_obj)
            except Exception:
                self.gateway = Gateway(self.channel)

        self.network = self.gateway.get_network(self.settings.FABRIC_CHANNEL_NAME)
        self.contract = self.network.get_contract(self.settings.FABRIC_CHAINCODE_NAME)
        self.is_connected = True
        return _AwaitableNone()

    async def submit_record_audit_event(self, event_json_str: str) -> str:
        """Submit RecordAuditEvent transaction to the ordering service.

        Returns:
            The Fabric transaction ID string.
        """
        if self.contract is None:
            raise RuntimeError("Fabric gateway is not connected. Call connect() first.")

        if hasattr(self.contract, "submit_async"):
            res = self.contract.submit_async("RecordAuditEvent", event_json_str)
            result_bytes = await res if inspect.isawaitable(res) else res
        elif hasattr(self.contract, "submit_transaction"):
            res = self.contract.submit_transaction("RecordAuditEvent", event_json_str)
            result_bytes = await res if inspect.isawaitable(res) else res
        else:
            raise AttributeError("Contract has neither submit_async nor submit_transaction")

        if isinstance(result_bytes, bytes):
            return result_bytes.decode("utf-8")
        return str(result_bytes)

    async def evaluate_read_audit_event(self, event_id: str) -> Dict[str, Any]:
        """Query the ledger state for a specific audit event by event_id."""
        if self.contract is None:
            raise RuntimeError("Fabric gateway is not connected. Call connect() first.")

        if hasattr(self.contract, "evaluate_async"):
            res = self.contract.evaluate_async("ReadAuditEvent", event_id)
            result_bytes = await res if inspect.isawaitable(res) else res
        elif hasattr(self.contract, "evaluate_transaction"):
            res = self.contract.evaluate_transaction("ReadAuditEvent", event_id)
            result_bytes = await res if inspect.isawaitable(res) else res
        else:
            raise AttributeError("Contract has neither evaluate_async nor evaluate_transaction")

        if isinstance(result_bytes, dict):
            return result_bytes
        raw_str = result_bytes.decode("utf-8") if isinstance(result_bytes, bytes) else str(result_bytes)
        return json.loads(raw_str)

    async def evaluate_get_all_audit_events(self) -> List[Dict[str, Any]]:
        """Query the ledger state for all audit events recorded on chain."""
        if self.contract is None:
            raise RuntimeError("Fabric gateway is not connected. Call connect() first.")

        if hasattr(self.contract, "evaluate_async"):
            res = self.contract.evaluate_async("GetAllAuditEvents")
            result_bytes = await res if inspect.isawaitable(res) else res
        elif hasattr(self.contract, "evaluate_transaction"):
            res = self.contract.evaluate_transaction("GetAllAuditEvents")
            result_bytes = await res if inspect.isawaitable(res) else res
        else:
            raise AttributeError("Contract has neither evaluate_async nor evaluate_transaction")

        if isinstance(result_bytes, list):
            return result_bytes
        raw_str = result_bytes.decode("utf-8") if isinstance(result_bytes, bytes) else str(result_bytes)
        return json.loads(raw_str)

    async def close(self) -> None:
        """Close the gateway connection and the gRPC channel."""
        if self.gateway is not None:
            if hasattr(self.gateway, "close"):
                res = self.gateway.close()
                if inspect.isawaitable(res):
                    await res
            self.gateway = None

        if self.channel is not None:
            if hasattr(self.channel, "close"):
                res = self.channel.close()
                if inspect.isawaitable(res):
                    await res
            self.channel = None

        self.network = None
        self.contract = None
        self.is_connected = False
