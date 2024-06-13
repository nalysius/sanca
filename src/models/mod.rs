//! In this module are declared the entities manipulated by this program

pub mod cve;
pub mod reqres;
pub mod technology;

use clap::{builder::PossibleValue, ValueEnum};

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
    pub fn new(
        technology: &str,
        version: Option<&str>,
        evidence: &str,
        evidence_text: &str,
        url_of_finding: Option<&str>,
    ) -> Self {
        Finding {
            technology: technology.to_string(),
            version: version.map(|f| f.to_string()),
            evidence: evidence.to_string(),
            evidence_text: evidence_text.to_string(),
            url_of_finding: url_of_finding.map(|f| f.to_string()),
        }
    }

    /// Read the CVEs in the directory and add the ones concerning the current finding.
    ///
    /// If cve_dir isn't a valid path or not readable, an Err is returned.
    /// Otherwise, nothing is returned.
    pub fn check_cves(&mut self, _cve_dir: String) {
        // TODO
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
