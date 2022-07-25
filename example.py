import asyncio
import webbrowser

from discord_remote_auth import PendingRemoteInit, RemoteAuth

auth = RemoteAuth()


@auth.pending_remote_init
async def pending_remote_init(fingerprint: PendingRemoteInit):
    # Scan this with your phone
    webbrowser.open(
        f"https://api.qrserver.com/v1/create-qr-code/?data=https://discord.com/ra/{fingerprint['fingerprint']}"
    )


@auth.finish
async def finish(token: str):
    print(token)  # Either get the token with @auth.finish or


asyncio.run(auth.auth())
