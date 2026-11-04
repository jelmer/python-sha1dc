# python-sha1dc

Python bindings for the Rust [`sha1dc`](https://crates.io/crates/sha1dc)
crate: SHA-1 with collision detection.

The API mirrors `hashlib.sha1`. Methods that produce a digest raise
`Sha1CollisionError` when a SHA-1 collision attack is detected in the input,
so a caller that treats the digest as an identity does not accept the
attacker's forged value.

## Usage

```python
import sha1dc

h = sha1dc.sha1(b"hello ")
h.update(b"world")
print(h.hexdigest())
# 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed

try:
    sha1dc.digest(open("shattered-1.pdf", "rb").read())
except sha1dc.Sha1CollisionError as exc:
    forged_digest, forged_hex = exc.args
    print("refusing colliding digest:", forged_hex)
```

A `mitigate` variant is also available for cases where you must still produce
a usable, non-standard digest from attacking input; see `sha1dc.mitigate`.

## Building

```sh
pip install maturin
maturin develop --release
```

## License

Apache-2.0
