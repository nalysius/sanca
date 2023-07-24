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
pub mod proftpd;
pub mod pureftpd;

use crate::models::{Finding, Technology, UrlResponse};
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
    /// "version" & "wholematch" MUST be present. It may change in the future.
    /// TODO: make the code more flexible, so other web checkers will be able to use it
    /// too.
    ///
    /// If evidence is longer than evidence_first_chars + evidence_last_chars,
    /// it will be cut in the middle. So, only the given number of chars will
    /// remains at the beginning, and the other given number for the end.
    fn extract_finding_from_captures(
        &self,
        captures: Captures,
        url_response: &UrlResponse,
        evidence_first_chars: usize,
        evidence_last_chars: usize,
        technology_name: &str,
    ) -> Finding {
        let mut evidence = captures["wholematch"].to_string();
        let evidence_length = evidence.len();
        if evidence_length > evidence_first_chars + evidence_last_chars {
            let evidencep1 = evidence[0..evidence_first_chars].to_string();
            let evidencep2 = evidence[evidence_length - evidence_last_chars..].to_string();
            evidence = format!("{}[...]{}", evidencep1, evidencep2);
        }

        let version = captures["version"].to_string();
        // Add a space in the version, so in the evidence text we
        // avoid a double space if the version is not found
        let version_text = format!(" {}", version);

        let evidence_text = format!(
            "{}{} has been identified because we found \"{}\" at this url: {}",
            technology_name, version_text, evidence, url_response.url
        );

        return Finding::new(
            technology_name,
            Some(&version),
            &evidence,
            &evidence_text,
            Some(&url_response.url),
        );
    }
}
