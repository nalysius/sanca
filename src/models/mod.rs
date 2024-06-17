//! In this module are declared the entities manipulated by this program

pub mod reqres;
pub mod technology;

use crate::vulnerabilities::fetchers::nvd::Vulnerability;
use clap::{builder::PossibleValue, ValueEnum};
use serde::{Deserialize, Serialize};
use std::convert::From;
use technology::Technology;

/// Represents the type of scan
#[derive(Clone, Copy, Debug, PartialEq)]
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

/// Represents a finding of a technology running on an asset
pub struct Finding {
    /// The technology found
    pub technology: Technology,
    /// The version of the technology
    /// Optional since it can be unknown
    pub version: Option<String>,
    /// The evidence of the finding
    pub evidence: String,
    /// The text for the evidence
    pub evidence_text: String,
    /// The URL where the finding has been found.
    pub url_of_finding: Option<String>,
    /// The list of vulnerabilities.
    pub vulnerabilities: Vec<CVE>,
}

impl Finding {
    /// Creates a new finding
    pub fn new(
        technology: Technology,
        version: Option<&str>,
        evidence: &str,
        evidence_text: &str,
        url_of_finding: Option<&str>,
    ) -> Self {
        Finding {
            technology: technology,
            version: version.map(|f| f.to_string()),
            evidence: evidence.to_string(),
            evidence_text: evidence_text.to_string(),
            url_of_finding: url_of_finding.map(|f| f.to_string()),
            vulnerabilities: Vec::new(),
        }
    }
}

impl PartialEq for Finding {
    /// Two findings are equal if their technology and version are the same
    fn eq(&self, other: &Self) -> bool {
        return self.technology == other.technology && self.version == other.version;
    }
}

/// An enum to match the available writers
#[derive(Clone, Debug, PartialEq)]
pub enum Writers {
    /// StdoutWriter
    TextStdout,
    /// CsvWriter
    Csv,
}

impl ValueEnum for Writers {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::TextStdout, Self::Csv]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            Self::TextStdout => Some(PossibleValue::new("textstdout")),
            Self::Csv => Some(PossibleValue::new("csv")),
        }
    }
}

/// Represents a CVE, as embedded in a Finding.
#[derive(Clone, Deserialize, Serialize)]
pub struct CVE {
    /// The CVE identifier.
    /// Example: CVE-2012-6708
    pub cve_id: String,
    /// The base score.
    /// Example: 8.3
    pub base_score: f32,
    /// The CVSS version.
    pub cvss_version: String,
}

/// Implements from Vulnerability instead of NVD CVE, because it's
/// upper in the NVD response hierarchy and will be simpler to call.
impl From<Vulnerability> for CVE {
    fn from(vuln: Vulnerability) -> Self {
        let cve_id = vuln.cve.id.clone();
        let metrics = vuln.cve.metrics;
        let mut base_score = 0.0;
        let mut cvss_version = String::new();
        if let Some(metric) = metrics.cvss_metric_v31 {
	    if !metric.is_empty() {
		base_score = metric[0].cvss_data.base_score;
		cvss_version = "3.1".to_string();
	    }
        } else if let Some(metric) = metrics.cvss_metric_v30 {
	    if !metric.is_empty() {
		base_score = metric[0].cvss_data.base_score;
		cvss_version = "3.0".to_string();
	    }
        } else if let Some(metric) = metrics.cvss_metric_v2 {
	    if !metric.is_empty() {
		base_score = metric[0].cvss_data.base_score;
		cvss_version = "2".to_string();
	    }
        }

        Self {
            cve_id,
            base_score,
            cvss_version,
        }
    }
}

impl PartialEq for CVE {
    /// Two CVE are equal if they have the same identifier.
    fn eq(&self, other: &Self) -> bool {
        return self.cve_id == other.cve_id;
    }
}
