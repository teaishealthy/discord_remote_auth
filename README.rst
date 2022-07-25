discord_remote_auth
===================

Installation
~~~~~~~~~~~~

``discord_remote_auth`` is currently not available on pip, to install it run

.. code-block:: bash

   $ pip install git+https://github.com/teaishealthy/discord_remote_auth



Example
~~~~~~~
.. code-block:: py

   import asyncio
   import webbrowser

   from discord_remote_auth import RemoteAuth, PendingRemoteInit

   auth = RemoteAuth()


   @auth.pending_remote_init
   async def pending_remote_init(fingerprint: PendingRemoteInit):
      # Scan this with your phone
      webbrowser.open(
         f"https://api.qrserver.com/v1/create-qr-code/?data=https://discord.com/ra/{fingerprint['fingerprint']}"
      )


   @auth.finish
   async def finish(token: str):
      print(token)  # Either get the token here or

   # here
   token = asyncio.run(auth.auth())

This example will open your default webbrowser and show you a QR code to scan with your phone,
once you have scanned the code, the access token will be printed.


Credits
~~~~~~~

Luna for the `unofficial-api-docs <https://luna.gitlab.io/discord-unofficial-docs>`_

Vap0r1ze for `<https://github.com/Vap0r1ze/discord-remote-auth>`_ which has helped as a reference for discord's encryption