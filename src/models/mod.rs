//! In this module are declared the entities manipulated by this program

use clap::{ValueEnum, builder::PossibleValue};

/// Represents the type of scan
#[derive(Clone, PartialEq, Debug)]
pub enum ScanType {
    /// Protocol TCP
    Tcp,
    /// Protocol UDP (not supported yet)
    Udp,
    /// Protocol HTTP
    Http,
}

impl ValueEnum for ScanType {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[ScanType::Tcp, ScanType::Http, ScanType::Udp]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            ScanType::Tcp => Some(PossibleValue::new("tcp")),
            ScanType::Http => Some(PossibleValue::new("http")),
            ScanType::Udp => Some(PossibleValue::new("udp")),
        }
    }
}


/// Represents an asset to scan
pub struct Asset {
    /// The IP address or hostname of the asset
    /// A target can be scanned either by its IP address or its hostname
    pub ip_hostname: String,
    /// The list of ports to scan on the asset
    pub ports_to_scan: Vec<u16>,
}

/// Represents a finding of a technology running on an asset
pub struct Finding {
    /// The technology found
    pub technology: String,
    /// The version of the technology
    /// Optional since it can be unknown
    pub version: Option<String>,
    /// The evidence of the finding
    pub evidence: String,
    /// The text for the evidence
    pub evidence_text: String,
    /// The URL where the finding has been found.
    pub url_of_finding: Option<String>,
}

impl Finding {
    /// Creates a new finding
    pub fn new(technology: &str, version: Option<&str>, evidence: &str, evidence_text: &str, url_of_finding: Option<&str>) -> Self {
        Finding {
            technology: technology.to_string(),
            version: version.map(|f| f.to_string()),
            evidence: evidence.to_string(),
            evidence_text: evidence_text.to_string(),
            url_of_finding: url_of_finding.map(|f| f.to_string())
        }
    }
}