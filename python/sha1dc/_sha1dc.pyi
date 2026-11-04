from collections.abc import Buffer
from typing import final

digest_size: int
block_size: int

class Sha1CollisionError(ValueError):
    """Raised when a SHA-1 collision attack is detected.

    Args are ``(digest, hexdigest)`` carrying the plain SHA-1 of the input.
    """

    args: tuple[bytes, str]

class Sha1MitigatedError(ValueError):
    """Raised by :class:`MitigatedSha1DC` when an attack is detected.

    Args are ``(digest, hexdigest)`` carrying the mitigated digest.
    """

    args: tuple[bytes, str]

@final
class Sha1DC:
    name: str
    digest_size: int
    block_size: int
    collision_detected: bool

    def __init__(self, data: Buffer | None = ...) -> None: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> Sha1DC: ...

@final
class MitigatedSha1DC:
    name: str
    digest_size: int
    block_size: int
    collision_detected: bool

    def __init__(self, data: Buffer | None = ...) -> None: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> MitigatedSha1DC: ...

def digest(data: Buffer | None = ...) -> bytes: ...
def hexdigest(data: Buffer | None = ...) -> str: ...
