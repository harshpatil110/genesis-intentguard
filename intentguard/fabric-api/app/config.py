"""Fabric API Gateway Configuration.

Loads Hyperledger Fabric 2.5.16 network crypto paths and peer connection parameters.
"""

from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class FabricSettings(BaseSettings):
    """Hyperledger Fabric Gateway connection settings and cryptographic paths."""

    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_PEER_ENDPOINT: str = "localhost:7051"
    FABRIC_PEER_HOST_ALIAS: str = "peer0.org1.example.com"
    FABRIC_CHANNEL_NAME: str = "intentguard"
    FABRIC_CHAINCODE_NAME: str = "intentguard"
    FABRIC_CRYPTO_PATH: str = "/home/user/fabric-dev/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
    FABRIC_API_KEY: str = "intentguard_local_dev_key"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def tls_cert_path(self) -> str:
        """Absolute or relative path to the TLS root certificate."""
        base = self.FABRIC_CRYPTO_PATH.rstrip("/\\")
        return f"{base}/peers/peer0.org1.example.com/tls/ca.crt"

    @property
    def cert_path(self) -> str:
        """Absolute or relative path to the user signing certificate (signcerts/cert.pem)."""
        base = self.FABRIC_CRYPTO_PATH.rstrip("/\\")
        return f"{base}/users/User1@org1.example.com/msp/signcerts/cert.pem"

    @property
    def key_path(self) -> str:
        """Absolute or relative path to the keystore directory containing the user private key."""
        base = self.FABRIC_CRYPTO_PATH.rstrip("/\\")
        return f"{base}/users/User1@org1.example.com/msp/keystore"

    @property
    def key_dir_path(self) -> str:
        """Alias for key_path."""
        return self.key_path


@lru_cache()
def get_fabric_settings() -> FabricSettings:
    """Return cached FabricSettings singleton instance."""
    return FabricSettings()


Settings = FabricSettings
