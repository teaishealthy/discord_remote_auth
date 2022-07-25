from __future__ import annotations

import asyncio
import hashlib
import logging
from base64 import b64decode, b64encode
from inspect import iscoroutinefunction
from typing import Any, Callable, Coroutine, Dict, Optional, TypeVar, Union

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from .types import (
    Cancel,
    ClientNonceProof,
    Finish,
    Hello,
    Init,
    PendingFinish,
    PendingRemoteInit,
    ServerNonceProof,
    UserPayload,
)

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
    "HEADERS",
    "RemoteAuth",
)

logger = logging.getLogger("discord-remote-auth-kit")
Coro = TypeVar("Coro", bound=Callable[..., Coroutine[Any, Any, Any]])
HEADERS = {
    "Origin": "https://discord.com",
}


class RemoteAuth:
    """The RemoteAuth object, handles connecting to the remote auth gateway"""

    def __init__(self) -> None:
        """Create a new RemoteAuth object"""
        self.priv = generate_private_key(65537, 2048)
        self.pub = self.priv.public_key()
        self.ws: aiohttp.ClientWebSocketResponse = None  # type: ignore
        self._coroutines: Dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}
        self._got_heartbeat_ack = True

    async def _heartbeat(self, ws: aiohttp.ClientWebSocketResponse, interval: int):
        await asyncio.sleep(interval / 1000)
        if not self._got_heartbeat_ack:
            raise RuntimeError("Heartbeat ack not received")
        logger.debug('> {"op": "heartbeat"}')
        await ws.send_json({"op": "heartbeat"})
        self._got_heartbeat_ack = False

    def _decrypt(self, data: str) -> bytes:
        return self.priv.decrypt(
            b64decode(data),
            OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), label=None),
        )

    async def auth(self) -> Optional[str]:
        """Run the full authentication process and return the access token

        Returns:
            Optional[str]: The access token if successful, None otherwise
        """
        async with aiohttp.ClientSession(headers=HEADERS) as session:
            self.ws: aiohttp.ClientWebSocketResponse
            async with session.ws_connect(  # type: ignore
                "wss://remote-auth-gateway.discord.gg/?v=1"
            ) as self.ws:
                task = await self._hello()

                await self._init()

                await self._nonce_proof()

                await self._pending_remote_init()

                await self._pending_finish()

                return await self._final(task)

    def _register(self, event: str, coroutine: Callable[..., Coroutine[Any, Any, Any]]):
        if not iscoroutinefunction(coroutine):
            raise TypeError(f"Expected coroutine, got {type(coroutine)}")
        self._coroutines[event] = coroutine

    async def _maybe_coro(self, event: str, *args: Any, **kwargs: Any) -> None:
        if event in self._coroutines:
            await self._coroutines[event](*args, **kwargs)

    async def _receive_json(self):
        while True:
            message = await self.ws.receive_json()
            if message["op"] != "heartbeat_ack":
                return message
            self._got_heartbeat_ack = True

    def hello(self, coroutine: Coro) -> Coro:
        """Hi ooliver"""
        self._register("hello", coroutine)
        return coroutine

    def nonce_proof(self, coroutine: Coro) -> Coro:
        """Register an coroutine for the `nonce_proof` event handler"""
        self._register("nonce_proof", coroutine)
        return coroutine

    def pending_remote_init(self, coroutine: Coro) -> Coro:
        """Register an coroutine for the `hello` event handler"""
        self._register("pending_remote_init", coroutine)
        return coroutine

    def pending_finish(self, coroutine: Coro) -> Coro:
        """Register an coroutine for the `pending_finish` event handler"""

        self._register("pending_finish", coroutine)
        return coroutine

    def finish(self, coroutine: Coro) -> Coro:
        """Register an coroutine for the `finish` event handler"""

        self._register("finish", coroutine)
        return coroutine

    def cancel(self, coroutine: Coro) -> Coro:
        """Register an coroutine for the `cancel` event handler"""

        self._register("cancel", coroutine)
        return coroutine

    async def _hello(self) -> asyncio.Task[Any]:
        hello: Hello = await self._receive_json()
        await self._maybe_coro("hello", hello)
        logger.info(f"< {hello}")
        return asyncio.get_event_loop().create_task(
            self._heartbeat(self.ws, hello["heartbeat_interval"])
        )

    async def _init(self):
        encoded_public_key = b64encode(
            self.pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        init: Init = {"op": "init", "encoded_public_key": encoded_public_key}
        logger.info(f"> {init}")
        await self.ws.send_json(init)

    async def _nonce_proof(self):
        message: ServerNonceProof = await self._receive_json()
        await self._maybe_coro("nonce_proof", message)
        logger.info(f"< {message}")
        decrypted_nonce = self._decrypt(message["encrypted_nonce"])
        hash_ = (
            b64encode(hashlib.sha256(decrypted_nonce).digest(), b"-_")
            .decode()
            .replace("=", "")
        )
        nonce_proof: ClientNonceProof = {"op": "nonce_proof", "proof": hash_}
        logger.info(f"> {nonce_proof}")
        await self.ws.send_json(nonce_proof)

    async def _pending_remote_init(self):
        message: PendingRemoteInit = await self._receive_json()
        await self._maybe_coro("pending_remote_init", message)
        logger.info(f"< {message}")
        return message["fingerprint"]

    async def _pending_finish(self):
        message: PendingFinish = await self._receive_json()
        logger.info(f"< {message}")
        payload = UserPayload.from_encrypted(
            self._decrypt(message["encrypted_user_payload"])
        )
        logger.info(f"Decrypted payload: {payload}")
        await self._maybe_coro("pending_finish", payload)
        return payload

    async def _final(self, task: asyncio.Task[Any]) -> Optional[str]:
        message: Union[Finish, Cancel] = await self._receive_json()
        logger.info(f"< {message}")

        task.cancel()

        if message["op"] == "finish":
            decrypted = self._decrypt(message["encrypted_token"]).decode()
            await self._maybe_coro("finish", decrypted)
            return decrypted
        await self._maybe_coro("cancel", message)
