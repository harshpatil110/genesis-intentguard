"""Unit and Integration Tests for Hyperledger Fabric Gateway Connector (Task 25)."""

import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure fabric-api root is on sys.path
FABRIC_API_ROOT = Path(__file__).resolve().parent.parent
if str(FABRIC_API_ROOT) not in sys.path:
    sys.path.insert(0, str(FABRIC_API_ROOT))

from app.config import FabricSettings, get_fabric_settings
from app.gateway_client import (
    FabricGatewayClient,
    read_file,
    read_first_file_in_dir,
)


def test_config_resolves_paths_correctly():
    """Ensure config.py computes the correct sub-paths for TLS, signcerts, and keystore relative to FABRIC_CRYPTO_PATH."""
    crypto_base = "/home/testuser/fabric-dev/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
    settings = FabricSettings(
        FABRIC_CRYPTO_PATH=crypto_base,
        FABRIC_MSP_ID="Org1MSP",
        FABRIC_PEER_ENDPOINT="localhost:7051",
        FABRIC_PEER_HOST_ALIAS="peer0.org1.example.com",
        FABRIC_CHANNEL_NAME="intentguard",
        FABRIC_CHAINCODE_NAME="intentguard",
    )

    assert settings.FABRIC_MSP_ID == "Org1MSP"
    assert settings.FABRIC_PEER_ENDPOINT == "localhost:7051"
    assert settings.FABRIC_PEER_HOST_ALIAS == "peer0.org1.example.com"
    assert settings.FABRIC_CHANNEL_NAME == "intentguard"
    assert settings.FABRIC_CHAINCODE_NAME == "intentguard"

    expected_tls = f"{crypto_base}/peers/peer0.org1.example.com/tls/ca.crt"
    expected_cert = f"{crypto_base}/users/User1@org1.example.com/msp/signcerts/cert.pem"
    expected_key = f"{crypto_base}/users/User1@org1.example.com/msp/keystore"

    assert settings.tls_cert_path == expected_tls
    assert settings.cert_path == expected_cert
    assert settings.key_path == expected_key
    assert settings.key_dir_path == expected_key


def test_get_fabric_settings_singleton():
    """Ensure get_fabric_settings returns a valid FabricSettings instance."""
    s1 = get_fabric_settings()
    s2 = get_fabric_settings()
    assert isinstance(s1, FabricSettings)
    assert s1 is s2


def test_gateway_client_raises_file_not_found_on_missing_certs():
    """Instantiate FabricGatewayClient and call connect(). Assert it catches missing cert paths gracefully."""
    settings = FabricSettings(
        FABRIC_CRYPTO_PATH="/non/existent/path/organizations/peerOrganizations/org1.example.com"
    )
    client = FabricGatewayClient(settings=settings)
    with pytest.raises(FileNotFoundError) as exc_info:
        client.connect()

    assert "File not found" in str(exc_info.value) or "not found" in str(exc_info.value)
    assert not client.is_connected


def test_file_reader_helpers(tmp_path: Path):
    """Test read_file and read_first_file_in_dir error handling and success cases."""
    # 1. Non-existent file
    missing_file = tmp_path / "missing.pem"
    with pytest.raises(FileNotFoundError):
        read_file(missing_file)

    # 2. Existing file
    good_file = tmp_path / "cert.pem"
    good_file.write_bytes(b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")
    data = read_file(good_file)
    assert b"BEGIN CERTIFICATE" in data

    # 3. Non-existent directory
    missing_dir = tmp_path / "keystore_missing"
    with pytest.raises(FileNotFoundError):
        read_first_file_in_dir(missing_dir)

    # 4. Empty directory
    empty_dir = tmp_path / "empty_keystore"
    empty_dir.mkdir()
    with pytest.raises(FileNotFoundError):
        read_first_file_in_dir(empty_dir)

    # 5. Directory with key file
    key_dir = tmp_path / "valid_keystore"
    key_dir.mkdir()
    key_file = key_dir / "priv_sk"
    key_file.write_bytes(b"-----BEGIN PRIVATE KEY-----\nMOCKKEY\n-----END PRIVATE KEY-----\n")
    key_data = read_first_file_in_dir(key_dir)
    assert b"BEGIN PRIVATE KEY" in key_data


@pytest.mark.asyncio
async def test_unconnected_client_raises_runtime_error():
    """Ensure methods throw RuntimeError if called before connect()."""
    client = FabricGatewayClient()
    with pytest.raises(RuntimeError, match="not connected"):
        await client.submit_record_audit_event('{"event_id": "test"}')

    with pytest.raises(RuntimeError, match="not connected"):
        await client.evaluate_read_audit_event("evt-1")

    with pytest.raises(RuntimeError, match="not connected"):
        await client.evaluate_get_all_audit_events()


@pytest.mark.asyncio
async def test_gateway_client_submit_and_evaluate_methods(tmp_path: Path):
    """Test connect, submit_record_audit_event, evaluate_read_audit_event, evaluate_get_all, and close with mocks."""
    # Setup mock file structure
    tls_dir = tmp_path / "peers" / "peer0.org1.example.com" / "tls"
    tls_dir.mkdir(parents=True)
    tls_file = tls_dir / "ca.crt"
    tls_file.write_bytes(b"-----BEGIN CERTIFICATE-----\nTLS_CA\n-----END CERTIFICATE-----\n")

    signcert_dir = tmp_path / "users" / "User1@org1.example.com" / "msp" / "signcerts"
    signcert_dir.mkdir(parents=True)
    signcert_file = signcert_dir / "cert.pem"
    signcert_file.write_bytes(b"-----BEGIN CERTIFICATE-----\nUSER_CERT\n-----END CERTIFICATE-----\n")

    keystore_dir = tmp_path / "users" / "User1@org1.example.com" / "msp" / "keystore"
    keystore_dir.mkdir(parents=True)
    key_file = keystore_dir / "priv_sk"
    key_file.write_bytes(b"-----BEGIN PRIVATE KEY-----\nUSER_KEY\n-----END PRIVATE KEY-----\n")

    settings = FabricSettings(
        FABRIC_CRYPTO_PATH=str(tmp_path),
        FABRIC_PEER_ENDPOINT="localhost:7051",
        FABRIC_PEER_HOST_ALIAS="peer0.org1.example.com",
        FABRIC_CHANNEL_NAME="intentguard",
        FABRIC_CHAINCODE_NAME="intentguard",
    )

    with patch("app.gateway_client.Gateway") as mock_gateway_cls, \
         patch("app.gateway_client.grpc.aio.secure_channel") as mock_secure_channel:

        mock_channel = MagicMock()
        mock_channel.close = AsyncMock()
        mock_secure_channel.return_value = mock_channel

        mock_contract = MagicMock()
        mock_contract.submit_async = AsyncMock(return_value=b"mock-tx-123")
        mock_contract.evaluate_async = AsyncMock(return_value=b'{"event_id": "evt-1", "action": "BLOCKED"}')

        mock_network = MagicMock()
        mock_network.get_contract.return_value = mock_contract

        mock_gateway = MagicMock()
        mock_gateway.get_network.return_value = mock_network
        mock_gateway.close = AsyncMock()
        mock_gateway_cls.return_value = mock_gateway

        client = FabricGatewayClient(settings=settings)
        # Verify connect works
        client.connect()

        assert client.is_connected is True
        mock_secure_channel.assert_called_once_with(
            target="localhost:7051",
            credentials=mock_secure_channel.call_args[1]["credentials"],
            options=(("grpc.ssl_target_name_override", "peer0.org1.example.com"),)
        )
        mock_gateway.get_network.assert_called_once_with("intentguard")
        mock_network.get_contract.assert_called_once_with("intentguard")

        # Test submit_record_audit_event
        tx_id = await client.submit_record_audit_event('{"event_id": "evt-1"}')
        assert tx_id == "mock-tx-123"
        mock_contract.submit_async.assert_awaited_once_with("RecordAuditEvent", '{"event_id": "evt-1"}')

        # Test evaluate_read_audit_event
        read_res = await client.evaluate_read_audit_event("evt-1")
        assert read_res == {"event_id": "evt-1", "action": "BLOCKED"}
        mock_contract.evaluate_async.assert_awaited_with("ReadAuditEvent", "evt-1")

        # Test evaluate_get_all_audit_events
        mock_contract.evaluate_async = AsyncMock(
            return_value=b'[{"event_id": "evt-1"}, {"event_id": "evt-2"}]'
        )
        all_events = await client.evaluate_get_all_audit_events()
        assert len(all_events) == 2
        assert all_events[0]["event_id"] == "evt-1"
        assert all_events[1]["event_id"] == "evt-2"
        mock_contract.evaluate_async.assert_awaited_with("GetAllAuditEvents")

        # Test close
        await client.close()
        assert client.is_connected is False
        assert client.gateway is None
        assert client.channel is None
        mock_gateway.close.assert_awaited_once()
        mock_channel.close.assert_awaited_once()
