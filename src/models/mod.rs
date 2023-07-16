//! In this module are declared the entities manipulated by this program

use clap::{ValueEnum, builder::PossibleValue};

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

/// An enumeration to represent the technologies that Sanca can tried to identify.
/// In practice it is useful mainly for the web technologies to send only
/// HTTP requests needed to identify the given technologies.
/// As an example, it's not needed to send a request at /phpinfo.php
/// if we want to identify only the JavaScript libraries.
#[derive(Clone, PartialEq, Debug)]
pub enum Technology {
    Dovecot,
    Exim,
    MariaDB,
    MySQL,
    OpenSSH,
    ProFTPD,
    PureFTPd,
    /// OS is generic for all OSes.
    OS,
    /// JS is generic for all JavaScript libraries.
    JS,
    PHP,
    PhpMyAdmin,
    Typo3,
    WordPress,
    Drupal,
}

impl Technology {
    /// Returns the scan types matching the technology
    pub fn get_scans(&self) -> Vec<ScanType> {
        match self {
            Self::Dovecot | Self::Exim => vec![ScanType::Tcp],
            Self::MariaDB | Self::MySQL => vec![ScanType::Tcp],
            Self::OpenSSH | Self::ProFTPD | Self::PureFTPd => vec![ScanType::Tcp],
            Self::OS => vec![ScanType::Tcp, ScanType::Http],
            Self::JS | Self::PHP | Self::PhpMyAdmin => vec![ScanType::Http],
            Self::WordPress | Self::Drupal | Self::Typo3 => vec![ScanType::Http],
        }
    }

    /// Checks whether the technology supports the given scan type
    pub fn supports_scan(&self, scan_type: ScanType) -> bool {
        self.get_scans().contains(&scan_type)
    }
}

impl ValueEnum for Technology {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Technology::Dovecot, Technology::Exim, Technology::MariaDB, Technology::MySQL,
            Technology::OpenSSH, Technology::ProFTPD, Technology::PureFTPd, Technology::OS,
            Technology::JS, Technology::PHP, Technology::PhpMyAdmin, Technology::WordPress,
            Technology::Drupal, Technology::Typo3,
        ]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            Technology::Dovecot => Some(PossibleValue::new("dovecot")),
            Technology::Exim => Some(PossibleValue::new("exim")),
            Technology::MariaDB => Some(PossibleValue::new("mariadb")),
            Technology::MySQL => Some(PossibleValue::new("mysql")),
            Technology::OpenSSH => Some(PossibleValue::new("openssh")),
            Technology::ProFTPD => Some(PossibleValue::new("proftpd")),
            Technology::PureFTPd => Some(PossibleValue::new("pureftpd")),
            Technology::OS => Some(PossibleValue::new("os")),
            Technology::JS => Some(PossibleValue::new("js")),
            Technology::PHP => Some(PossibleValue::new("PHP")),
            Technology::PhpMyAdmin => Some(PossibleValue::new("phpmyadmin")),
            Technology::WordPress => Some(PossibleValue::new("wordpress")),
            Technology::Drupal => Some(PossibleValue::new("drupal")),
            Technology::Typo3 => Some(PossibleValue::new("typo3")),
        }
    }
}
