"""SHA-1 with collision detection, in *mitigate* mode.

Use this variant when you must produce a usable digest from an input that may
be part of a collision attack and no external system needs to agree with the
value. Honest inputs give plain SHA-1; attacking inputs give a derived digest
that is not shared with the colliding message. In both cases, a detected
attack is still reported: finalization raises :class:`Sha1MitigatedError`
carrying the mitigated digest.
"""

from collections.abc import Buffer

from ._sha1dc import MitigatedSha1DC, Sha1MitigatedError

sha1 = MitigatedSha1DC


def new(data: Buffer = b"") -> MitigatedSha1DC:
    """Return a new mitigating SHA-1 hasher."""
    return MitigatedSha1DC(data)


__all__ = ["MitigatedSha1DC", "Sha1MitigatedError", "new", "sha1"]
