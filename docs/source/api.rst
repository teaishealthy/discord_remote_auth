API Reference
=============

.. module:: discord_remote_auth

RemoteAuth
~~~~~~~~~~

.. autoclass:: RemoteAuth
    :members:
    :exclude-members: hello, nonce_proof, pending_remote_init, pending_finish, finish, cancel, auth

    .. automethod:: RemoteAuth.auth

    .. automethod:: RemoteAuth.hello(self, coroutine)
        :decorator:

        :annotation:
    .. automethod:: RemoteAuth.nonce_proof(self, coroutine)
        :decorator:

        :annotation:
    .. automethod:: RemoteAuth.pending_remote_init(self, coroutine)
        :decorator:

        :annotation:
    .. automethod:: RemoteAuth.pending_finish(self, coroutine)
        :decorator:

        :annotation:
    .. automethod:: RemoteAuth.finish(self, coroutine)
        :decorator:

        :annotation:
    .. automethod:: RemoteAuth.cancel(self, coroutine)
        :decorator:

        :annotation:


Types
~~~~~

.. automodule:: discord_remote_auth.types
    :members:
    :exclude-members: UserPayload
    :undoc-members:

.. autoclass:: discord_remote_auth.types.UserPayload
    :members:
    :exclude-members: from_encrypted
