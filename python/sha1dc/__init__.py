"""SHA-1 with collision detection.

The :class:`sha1` class mirrors :class:`hashlib.sha1`. Methods that produce a
final digest (:meth:`~sha1.digest`, :meth:`~sha1.hexdigest`) raise
:class:`Sha1CollisionError` if a SHA-1 collision attack is detected in the
input. The exception carries the plain SHA-1 digest and its hex form; that
digest must not be trusted as an identifier, because an attacker has produced
two messages that share it.

For a variant that returns a non-standard digest derived from an attack input
(instead of the colliding one), see :mod:`sha1dc.mitigate`.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from . import mitigate
from ._sha1dc import (
    MitigatedSha1DC,
    Sha1CollisionError,
    Sha1DC,
    Sha1MitigatedError,
    block_size,
    digest,
    digest_size,
    hexdigest,
)

if TYPE_CHECKING:
    if sys.version_info >= (3, 12):
        from collections.abc import Buffer
    else:
        from typing_extensions import Buffer

sha1 = Sha1DC


def new(data: Buffer = b"") -> Sha1DC:
    """Return a new SHA-1 hasher with collision detection.

    Matches the :func:`hashlib.new` style factory. ``data`` is optional initial
    input and may be any bytes-like object (``bytes``, ``bytearray``,
    ``memoryview``, ...).
    """
    return Sha1DC(data)


__all__ = [
    "MitigatedSha1DC",
    "Sha1CollisionError",
    "Sha1DC",
    "Sha1MitigatedError",
    "block_size",
    "digest",
    "digest_size",
    "hexdigest",
    "mitigate",
    "new",
    "sha1",
]
