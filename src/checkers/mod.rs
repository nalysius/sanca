//! This module declares all the checkers.
//! A checker is a struct that checks an input (banner, HTTP headers, etc)
//! to against a technology.

pub mod dovecot;
pub mod exim;
pub mod handlebars;
pub mod httpd;
pub mod jquery;
pub mod lodash;
pub mod mariadb;
pub mod mysql;
pub mod nginx;
pub mod openssh;
pub mod openssl;
pub mod os;
pub mod php;
pub mod phpmyadmin;
pub mod proftpd;
pub mod pureftpd;

use crate::models::{Finding, Technology, UrlResponse};
use log::trace;
use regex::Captures;

/// A common interface between all TCP checkers
pub trait TcpChecker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide more information.
    fn check_tcp(&self, data: &[String]) -> Option<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;
}

/// A common interface between all HTTP checkers
pub trait HttpChecker {
    /// Checks data to determine if a given technology matches.
    /// data will contain information about HTTP request & response.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;

    /// Extract a finding from captures
    /// It is a common method used by most JavaScript checkers, so
    /// it's easier to defined it here.
    ///
    /// Actually it searches for the regex groups "wholematch" and "version".
    /// "wholematch" MUST be present. It is used as the evidence, and is
    /// truncated if needed.
    ///
    /// If the evidence (wholematch) is longer than evidence_first_chars + evidence_last_chars,
    /// it will be cut in the middle. So, only the given number of chars will
    /// remains at the beginning, and the other given number for the end.
    fn extract_finding_from_captures(
        &self,
        captures: Captures,
        url_response: &UrlResponse,
        evidence_first_chars: usize,
        evidence_last_chars: usize,
        technology_name: &str,
        evidence_text_templace: &str,
    ) -> Finding {
        trace!("Running HttpChecker::extract_finding_from_captures()");
        let mut evidence = captures["wholematch"].to_string();
        trace!("Evidence: {}", evidence);
        let evidence_length = evidence.len();
        if evidence_length > evidence_first_chars + evidence_last_chars {
            trace!("Evidence is too long, truncate it");
            let evidencep1 = evidence[0..evidence_first_chars].to_string();
            let evidencep2 = evidence[evidence_length - evidence_last_chars..].to_string();
            evidence = format!("{}[...]{}", evidencep1, evidencep2);
            trace!("New evidence: {}", evidence);
        }

        let mut version = None;
        let mut version_text = String::new();
        let version_match = captures.name("version");
        if version_match.is_some() {
            version = Some(version_match.unwrap().as_str());
            // Add a space in the version, so in the evidence text we
            // avoid a double space if the version is not found
            version_text = format!(" {}", version.unwrap());
            trace!("Version: {}", version_text);
        }

        let evidence_text = evidence_text_templace
            .replace("$techno_name$", technology_name)
            .replace("$techno_version$", &version_text)
            .replace("$evidence$", &evidence)
            .replace("$url_of_finding$", &url_response.url);

        trace!("Evidence text: {}", evidence_text);

        return Finding::new(
            technology_name,
            version,
            &evidence,
            &evidence_text,
            Some(&url_response.url),
        );
    }
}
