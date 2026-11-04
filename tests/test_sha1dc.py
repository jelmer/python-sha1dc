"""Tests for the sha1dc Python bindings.

These check that the public API matches hashlib.sha1 for honest inputs.
Collision-detection behaviour itself is covered by the upstream ``sha1dc``
Rust crate's own test suite; here we only verify the Python binding plumbing.
"""

import array
import hashlib

import pytest
import sha1dc

HELLO_WORLD_HEX = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
EMPTY_HEX = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_hexdigest_matches_hashlib():
    msg = b"The quick brown fox jumps over the lazy dog"
    assert sha1dc.sha1(msg).hexdigest() == hashlib.sha1(msg).hexdigest()


def test_digest_matches_hashlib():
    msg = b"abc" * 1000
    assert sha1dc.sha1(msg).digest() == hashlib.sha1(msg).digest()


def test_empty_hexdigest():
    assert sha1dc.sha1().hexdigest() == EMPTY_HEX
    assert sha1dc.sha1(b"").hexdigest() == EMPTY_HEX


def test_incremental_matches_oneshot():
    h = sha1dc.sha1()
    h.update(b"hello ")
    h.update(b"world")
    assert h.hexdigest() == HELLO_WORLD_HEX


def test_copy_is_independent():
    h = sha1dc.sha1(b"hello ")
    h2 = h.copy()
    h.update(b"world")
    h2.update(b"there")
    assert h.hexdigest() == hashlib.sha1(b"hello world").hexdigest()
    assert h2.hexdigest() == hashlib.sha1(b"hello there").hexdigest()


def test_attributes():
    h = sha1dc.sha1()
    assert h.digest_size == 20
    assert h.block_size == 64
    assert h.name == "sha1-dc"
    assert sha1dc.digest_size == 20
    assert sha1dc.block_size == 64


def test_module_digest_functions():
    assert sha1dc.hexdigest(b"hello world") == HELLO_WORLD_HEX
    assert sha1dc.digest(b"") == bytes.fromhex(EMPTY_HEX)
    assert sha1dc.hexdigest() == EMPTY_HEX


def test_new_factory():
    assert sha1dc.new(b"hello world").hexdigest() == HELLO_WORLD_HEX
    assert sha1dc.new().hexdigest() == EMPTY_HEX


def test_collision_detected_flag_defaults_false():
    h = sha1dc.sha1(b"not an attack")
    h.hexdigest()
    assert h.collision_detected is False


def test_mitigate_honest_input_matches_plain_sha1():
    msg = b"hello world"
    assert sha1dc.mitigate.sha1(msg).hexdigest() == hashlib.sha1(msg).hexdigest()


def test_exceptions_are_valueerror_subclasses():
    assert issubclass(sha1dc.Sha1CollisionError, ValueError)
    assert issubclass(sha1dc.Sha1MitigatedError, ValueError)


@pytest.mark.parametrize(
    "factory",
    [
        lambda b: b,
        bytearray,
        memoryview,
        lambda b: array.array("B", b),
        lambda b: memoryview(b"XX" + b + b"YY")[2 : 2 + len(b)],
    ],
    ids=["bytes", "bytearray", "memoryview", "array.array", "memoryview-slice"],
)
def test_accepts_buffer_protocol(factory):
    data = b"hello world"
    assert sha1dc.sha1(factory(data)).hexdigest() == HELLO_WORLD_HEX
    assert sha1dc.digest(factory(data)) == bytes.fromhex(HELLO_WORLD_HEX)
    assert sha1dc.hexdigest(factory(data)) == HELLO_WORLD_HEX

    h = sha1dc.sha1()
    h.update(factory(data))
    assert h.hexdigest() == HELLO_WORLD_HEX


def test_rejects_str():
    with pytest.raises(TypeError, match="bytes-like"):
        sha1dc.sha1("not bytes")
    with pytest.raises(TypeError, match="bytes-like"):
        sha1dc.sha1().update("not bytes")
    with pytest.raises(TypeError, match="bytes-like"):
        sha1dc.digest("not bytes")


def test_rejects_non_byte_buffer():
    with pytest.raises(TypeError, match="bytes-like"):
        sha1dc.sha1(array.array("i", [1, 2, 3]))
