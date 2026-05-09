use std::net::IpAddr;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use ressrf_core::cloud::CloudProvider;
use ressrf_core::error::{DataTier, Error};
use ressrf_core::policy::{HeaderRules, PolicyBuilder, Preset, ProtocolRules};
use ressrf_core::{AuditEvent, AuditSink, Cidr, Policy, UriValidator};

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

pyo3::create_exception!(ressrf._core, RessrfBlockedError, pyo3::exceptions::PyException);

fn error_to_py(err: Error) -> PyErr {
    match err {
        Error::Blocked(reason) => {
            let reason_json =
                serde_json::to_string(&reason).unwrap_or_else(|_| format!("{reason:?}"));
            RessrfBlockedError::new_err(reason_json)
        }
        Error::Parse(detail) => PyValueError::new_err(format!("parse error: {detail}")),
        Error::DnsError(detail) => PyValueError::new_err(format!("DNS error: {detail}")),
        Error::Config(detail) => PyValueError::new_err(format!("config error: {detail}")),
        Error::PolicyFinalized => PyValueError::new_err("policy already finalized"),
    }
}

// ---------------------------------------------------------------------------
// Audit callback adapter
// ---------------------------------------------------------------------------

struct PyAuditSink {
    callback: Py<PyAny>,
}

unsafe impl Send for PyAuditSink {}
unsafe impl Sync for PyAuditSink {}

impl AuditSink for PyAuditSink {
    fn emit(&self, event: &AuditEvent) {
        if let Some(py) = Python::try_attach(|py| {
            let json_str = serde_json::to_string(event).unwrap_or_default();
            let _ = self.callback.call1(py, (json_str,));
            Some(())
        }) {
            let _ = py;
        }
    }
}

// ---------------------------------------------------------------------------
// CorePolicyBuilder
// ---------------------------------------------------------------------------

#[pyclass]
struct CorePolicyBuilder {
    inner: Option<PolicyBuilder>,
}

#[pymethods]
impl CorePolicyBuilder {
    #[new]
    #[pyo3(signature = (preset = "external_only"))]
    fn new(preset: &str) -> PyResult<Self> {
        let p = match preset {
            "internal_only" => Preset::InternalOnly,
            "external_only" => Preset::ExternalOnly,
            "none" => Preset::None,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown preset: {other}. Use 'internal_only', 'external_only', or 'none'"
                )));
            }
        };
        Ok(Self {
            inner: Some(PolicyBuilder::new(p)),
        })
    }

    fn add_denied(&mut self, cidrs: Vec<String>) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        let refs: Vec<&str> = cidrs.iter().map(|s| s.as_str()).collect();
        builder.add_denied(&refs);
        Ok(())
    }

    fn add_allowed(&mut self, cidrs: Vec<String>) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        let refs: Vec<&str> = cidrs.iter().map(|s| s.as_str()).collect();
        builder.add_allowed(&refs);
        Ok(())
    }

    #[pyo3(signature = (required = None, denied = None, auto_xff = false))]
    fn header_rules(
        &mut self,
        required: Option<Vec<String>>,
        denied: Option<Vec<String>>,
        auto_xff: bool,
    ) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        builder.header_rules(HeaderRules {
            required: required.unwrap_or_default(),
            denied: denied.unwrap_or_default(),
            auto_xff,
        });
        Ok(())
    }

    #[pyo3(signature = (allow_plaintext_http = false, require_https = true))]
    fn protocol_rules(
        &mut self,
        allow_plaintext_http: bool,
        require_https: bool,
    ) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        builder.protocol_rules(ProtocolRules {
            allow_plaintext_http,
            require_https,
        });
        Ok(())
    }

    fn with_cloud(&mut self, name: &str) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        let provider = match name {
            "aws" => CloudProvider::Aws,
            "azure" => CloudProvider::Azure,
            "gcp" => CloudProvider::Gcp,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown cloud provider: {other}. Use 'aws', 'azure', or 'gcp'"
                )));
            }
        };
        builder.with_cloud(provider);
        Ok(())
    }

    fn audit_sink(&mut self, callback: Py<PyAny>) -> PyResult<()> {
        let builder = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        let sink = PyAuditSink { callback };
        builder.audit_sink(Box::new(sink));
        Ok(())
    }

    fn build(&mut self) -> PyResult<CorePolicy> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyValueError::new_err("builder already consumed by build()"))?;
        let policy = builder.build();
        Ok(CorePolicy {
            inner: Arc::new(policy),
        })
    }
}

// ---------------------------------------------------------------------------
// CorePolicy
// ---------------------------------------------------------------------------

#[pyclass(frozen, from_py_object)]
#[derive(Clone)]
struct CorePolicy {
    inner: Arc<Policy>,
}

#[pymethods]
impl CorePolicy {
    fn is_network_allowed(&self, ips: Vec<String>) -> PyResult<()> {
        let parsed: Vec<IpAddr> = ips
            .iter()
            .map(|s| s.parse::<IpAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PyValueError::new_err(format!("invalid IP: {e}")))?;
        self.inner
            .is_network_allowed(&parsed)
            .map_err(error_to_py)
    }

    fn validate_url(&self, url: &str) -> PyResult<()> {
        let validator = UriValidator::default();
        validator
            .validate_url(url, Some(&self.inner))
            .map_err(error_to_py)
    }

    fn preset(&self) -> &'static str {
        match self.inner.preset() {
            Preset::InternalOnly => "internal_only",
            Preset::ExternalOnly => "external_only",
            Preset::None => "none",
        }
    }
}

// ---------------------------------------------------------------------------
// CoreUriValidator
// ---------------------------------------------------------------------------

#[pyclass]
struct CoreUriValidator {
    inner: UriValidator,
}

#[pymethods]
impl CoreUriValidator {
    #[new]
    fn new() -> Self {
        Self {
            inner: UriValidator::default(),
        }
    }

    fn add_trusted_suffixes(&mut self, suffixes: Vec<String>) {
        let refs: Vec<&str> = suffixes.iter().map(|s| s.as_str()).collect();
        self.inner.add_trusted_suffixes(&refs);
    }

    fn add_denied_suffixes(&mut self, suffixes: Vec<String>) {
        let refs: Vec<&str> = suffixes.iter().map(|s| s.as_str()).collect();
        self.inner.add_denied_suffixes(&refs);
    }

    fn with_cloud_provider(&mut self, name: &str) -> PyResult<()> {
        let provider = match name {
            "aws" => CloudProvider::Aws,
            "azure" => CloudProvider::Azure,
            "gcp" => CloudProvider::Gcp,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown cloud provider: {other}"
                )));
            }
        };
        self.inner.with_cloud_provider(provider);
        Ok(())
    }

    #[pyo3(signature = (url, policy = None))]
    fn validate_url(&self, url: &str, policy: Option<&CorePolicy>) -> PyResult<()> {
        let policy_ref = policy.map(|p| p.inner.as_ref());
        self.inner.validate_url(url, policy_ref).map_err(error_to_py)
    }

    fn is_trusted_domain(&self, domain: &str) -> bool {
        self.inner.is_trusted_domain(domain)
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

#[pyfunction]
fn parse_cidr<'py>(py: Python<'py>, cidr_str: &str) -> PyResult<Bound<'py, PyDict>> {
    let cidr = Cidr::parse(cidr_str, DataTier::UserDeny)
        .map_err(|e| PyValueError::new_err(format!("invalid CIDR: {e}")))?;
    let dict = PyDict::new(py);
    dict.set_item("network", format!("{cidr}"))?;
    dict.set_item("prefix_len", cidr.prefix_len())?;
    Ok(dict)
}

#[pyfunction]
fn cidr_contains(cidr_str: &str, ip_str: &str) -> PyResult<bool> {
    let cidr = Cidr::parse(cidr_str, DataTier::UserDeny)
        .map_err(|e| PyValueError::new_err(format!("invalid CIDR: {e}")))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| PyValueError::new_err(format!("invalid IP: {e}")))?;
    Ok(cidr.contains(ip))
}

#[pyfunction]
fn deny_reason_to_dict<'py>(py: Python<'py>, json_str: &str) -> PyResult<Bound<'py, PyDict>> {
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;
    json_value_to_py_dict(py, &value)
}

fn json_value_to_py_dict<'py>(
    py: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            dict.set_item(k, json_value_to_py_any(py, v)?)?;
        }
    }
    Ok(dict)
}

fn json_value_to_py_any<'py>(
    py: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyAny>> {
    match value {
        serde_json::Value::Null => Ok(py.None().into_bound(py)),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any())
            } else {
                Ok(py.None().into_bound(py))
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_value_to_py_any(py, item)?)?;
            }
            Ok(list.into_any())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py_any(py, v)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

#[pymodule]
fn _core(py: Python<'_>, m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    m.add_class::<CorePolicyBuilder>()?;
    m.add_class::<CorePolicy>()?;
    m.add_class::<CoreUriValidator>()?;
    m.add_function(wrap_pyfunction!(parse_cidr, m)?)?;
    m.add_function(wrap_pyfunction!(cidr_contains, m)?)?;
    m.add_function(wrap_pyfunction!(deny_reason_to_dict, m)?)?;
    m.add("RessrfBlockedError", py.get_type::<RessrfBlockedError>())?;
    Ok(())
}
