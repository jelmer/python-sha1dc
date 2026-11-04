//! Python bindings for the `sha1dc` crate.
//!
//! Exposes two hasher classes that mirror `hashlib.sha1`: `Sha1DC` (standard
//! digest, raises on detected collision) and `MitigatedSha1DC` (returns a
//! mitigated digest when an attack is detected, raising as well so the caller
//! knows the value is non-standard).

use std::ffi::CString;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyType};

use sha1dc::{Collision, Digest, Hasher, mitigate};

/// Calls `f` with the bytes of `obj`, which must be a `bytes` object or any
/// object supporting the buffer protocol over bytes (memoryview, bytearray,
/// `array.array('B', ...)`, numpy `uint8` arrays, ...). `PyBytes` is
/// zero-copy; other buffers are read in place through their borrowed memory
/// without an extra copy.
fn with_bytes<R>(obj: &Bound<'_, PyAny>, f: impl FnOnce(&[u8]) -> R) -> PyResult<R> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(f(b.as_bytes()));
    }

    let buf = PyBuffer::<u8>::get(obj).map_err(|_| {
        let type_name = obj
            .get_type()
            .name()
            .map(|n| n.to_string())
            .unwrap_or_else(|_| "?".to_string());
        PyTypeError::new_err(format!(
            "a bytes-like object is required, not '{}'",
            type_name
        ))
    })?;
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err(
            "buffer is not C-contiguous; pass bytes or a contiguous view",
        ));
    }
    // A u8 buffer with item_size 1 is a byte run. `PyBuffer::get` already
    // checked the format matches u8, and the GIL is held, so the memory is
    // live and cannot be freed under us. Concurrent mutation from Python
    // code is the caller's problem, same as for hashlib.
    let slice = unsafe {
        std::slice::from_raw_parts(buf.buf_ptr() as *const u8, buf.item_count())
    };
    Ok(f(slice))
}

const DIGEST_SIZE: usize = 20;
const BLOCK_SIZE: usize = 64;

static COLLISION_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static MITIGATED_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn hex_of(digest: &Digest) -> String {
    let bytes = digest.as_bytes();
    let mut s = String::with_capacity(DIGEST_SIZE * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn exc_type<'py>(py: Python<'py>, cell: &'static PyOnceLock<Py<PyType>>) -> Bound<'py, PyType> {
    cell.get(py)
        .expect("exception type not initialized")
        .bind(py)
        .clone()
}

fn raise_collision(py: Python<'_>, c: Collision) -> PyErr {
    let digest = c.digest();
    let args = (
        PyBytes::new(py, digest.as_bytes()).unbind(),
        hex_of(&digest),
    );
    PyErr::from_type(exc_type(py, &COLLISION_ERROR), args)
}

fn raise_mitigated(py: Python<'_>, m: mitigate::Mitigated) -> PyErr {
    let digest = m.digest();
    let args = (
        PyBytes::new(py, digest.as_bytes()).unbind(),
        hex_of(&digest),
    );
    PyErr::from_type(exc_type(py, &MITIGATED_ERROR), args)
}

/// Standard SHA-1 hasher with collision detection.
///
/// Mirrors `hashlib.sha1`. On a detected collision `digest()` and
/// `hexdigest()` raise `Sha1CollisionError`; the exception carries the
/// colliding (plain SHA-1) digest. `collision_detected` lets callers check
/// without raising.
#[pyclass(module = "sha1dc._sha1dc", name = "Sha1DC")]
struct Sha1DC {
    hasher: Hasher,
}

#[pymethods]
impl Sha1DC {
    #[new]
    #[pyo3(signature = (data=None))]
    fn new(data: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let mut hasher = Hasher::new();
        if let Some(obj) = data {
            with_bytes(obj, |b| hasher.update(b))?;
        }
        Ok(Self { hasher })
    }

    #[getter]
    fn name(&self) -> &'static str {
        "sha1-dc"
    }

    #[getter]
    fn digest_size(&self) -> usize {
        DIGEST_SIZE
    }

    #[getter]
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn update(&mut self, data: &Bound<'_, PyAny>) -> PyResult<()> {
        with_bytes(data, |b| self.hasher.update(b))
    }

    /// Whether a collision has been detected so far. Finalization processes
    /// the padding block, so this may become true only after `digest()`.
    #[getter]
    fn collision_detected(&self) -> bool {
        self.hasher.collision_detected()
    }

    fn digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        match self.hasher.clone().finalize() {
            Ok(d) => Ok(PyBytes::new(py, d.as_bytes())),
            Err(c) => Err(raise_collision(py, c)),
        }
    }

    fn hexdigest(&self, py: Python<'_>) -> PyResult<String> {
        match self.hasher.clone().finalize() {
            Ok(d) => Ok(hex_of(&d)),
            Err(c) => Err(raise_collision(py, c)),
        }
    }

    fn copy(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
        }
    }
}

/// SHA-1 hasher that produces a *mitigated* digest when a collision attack is
/// detected. The digest is non-standard (does not match other SHA-1
/// implementations) for attacking inputs; for honest inputs it is plain SHA-1.
#[pyclass(module = "sha1dc._sha1dc", name = "MitigatedSha1DC")]
struct MitigatedSha1DC {
    hasher: mitigate::Hasher,
}

#[pymethods]
impl MitigatedSha1DC {
    #[new]
    #[pyo3(signature = (data=None))]
    fn new(data: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let mut hasher = mitigate::Hasher::new();
        if let Some(obj) = data {
            with_bytes(obj, |b| hasher.update(b))?;
        }
        Ok(Self { hasher })
    }

    #[getter]
    fn name(&self) -> &'static str {
        "sha1-dc-mitigated"
    }

    #[getter]
    fn digest_size(&self) -> usize {
        DIGEST_SIZE
    }

    #[getter]
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn update(&mut self, data: &Bound<'_, PyAny>) -> PyResult<()> {
        with_bytes(data, |b| self.hasher.update(b))
    }

    #[getter]
    fn collision_detected(&self) -> bool {
        self.hasher.collision_detected()
    }

    fn digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        match self.hasher.clone().finalize() {
            Ok(d) => Ok(PyBytes::new(py, d.as_bytes())),
            Err(m) => Err(raise_mitigated(py, m)),
        }
    }

    fn hexdigest(&self, py: Python<'_>) -> PyResult<String> {
        match self.hasher.clone().finalize() {
            Ok(d) => Ok(hex_of(&d)),
            Err(m) => Err(raise_mitigated(py, m)),
        }
    }

    fn copy(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
        }
    }
}

/// One-shot hash. Returns the digest bytes, or raises `Sha1CollisionError`.
#[pyfunction]
#[pyo3(signature = (data=None))]
fn digest<'py>(py: Python<'py>, data: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyBytes>> {
    let result = match data {
        Some(obj) => with_bytes(obj, sha1dc::digest)?,
        None => sha1dc::digest(&[]),
    };
    match result {
        Ok(d) => Ok(PyBytes::new(py, d.as_bytes())),
        Err(c) => Err(raise_collision(py, c)),
    }
}

/// One-shot hash, returning a hex string.
#[pyfunction]
#[pyo3(signature = (data=None))]
fn hexdigest(py: Python<'_>, data: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    let result = match data {
        Some(obj) => with_bytes(obj, sha1dc::digest)?,
        None => sha1dc::digest(&[]),
    };
    match result {
        Ok(d) => Ok(hex_of(&d)),
        Err(c) => Err(raise_collision(py, c)),
    }
}

#[pymodule]
fn _sha1dc(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let base = py.get_type::<PyValueError>();

    let collision_err = PyErr::new_type(
        py,
        &CString::new("sha1dc._sha1dc.Sha1CollisionError").unwrap(),
        None,
        Some(&base),
        None,
    )?;
    let mitigated_err = PyErr::new_type(
        py,
        &CString::new("sha1dc._sha1dc.Sha1MitigatedError").unwrap(),
        None,
        Some(&base),
        None,
    )?;

    m.add("Sha1CollisionError", collision_err.bind(py))?;
    m.add("Sha1MitigatedError", mitigated_err.bind(py))?;

    COLLISION_ERROR
        .set(py, collision_err)
        .map_err(|_| PyValueError::new_err("Sha1CollisionError already initialized"))?;
    MITIGATED_ERROR
        .set(py, mitigated_err)
        .map_err(|_| PyValueError::new_err("Sha1MitigatedError already initialized"))?;

    m.add_class::<Sha1DC>()?;
    m.add_class::<MitigatedSha1DC>()?;
    m.add_function(wrap_pyfunction!(digest, m)?)?;
    m.add_function(wrap_pyfunction!(hexdigest, m)?)?;
    m.add("digest_size", DIGEST_SIZE)?;
    m.add("block_size", BLOCK_SIZE)?;
    Ok(())
}
