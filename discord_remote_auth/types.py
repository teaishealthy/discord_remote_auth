from typing import Literal, NamedTuple, Optional, TypedDict

__all__ = (
    "Hello",
    "Init",
    "ServerNonceProof",
    "ClientNonceProof",
    "PendingRemoteInit",
    "PendingFinish",
    "UserPayload",
    "Finish",
    "Cancel",
)


class Hello(TypedDict):
    op: Literal["hello"]
    timeout_ms: int
    heartbeat_interval: int


class Init(TypedDict):
    op: Literal["init"]
    encoded_public_key: str


class ServerNonceProof(TypedDict):
    op: Literal["nonce_proof"]
    encrypted_nonce: str


class ClientNonceProof(TypedDict):
    op: Literal["nonce_proof"]
    proof: str


class PendingRemoteInit(TypedDict):
    op: Literal["pending_remote_init"]
    fingerprint: str


class PendingFinish(TypedDict):
    op: Literal["pending_finish"]
    encrypted_user_payload: str


class UserPayload(NamedTuple):
    """An object representing the user currently trying to authenticate."""

    snowflake: int  #: The snowflake id
    discriminator: int  #: The discriminator
    avatar_hash: Optional[str]  #: The avatar hash, if available
    username: str  #: The username

    @classmethod
    def from_encrypted(cls, encrypted: bytes):
        snowflake, discriminator, avatar_hash, username = encrypted.decode(
            "utf8"
        ).split(":")
        return cls(int(snowflake), int(discriminator), avatar_hash, username)


class Finish(TypedDict):
    op: Literal["finish"]
    encrypted_token: str


class Cancel(TypedDict):
    op: Literal["cancel"]
