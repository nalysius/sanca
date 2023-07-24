//! The Handlebars checker.
//! This module contains the checker used to determine if Handlebars is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::{Captures, Regex};

/// The checker
pub struct HandlebarsChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> HandlebarsChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example:
        let comment_regex = Regex::new(
            r"\/\*\*![\s\*]+@license\s+(?P<wholematch>handlebars (v(?P<version>\d\.\d\.\d)))",
        )
        .unwrap();
        let source_code_regex = Regex::new(r#"(?P<wholematch>HandlebarsEnvironment;.*[a-zA-Z0-9]="(?P<version>\d+\.\d+\.\d+)";[a-zA-Z0-9]+\.VERSION=[a-zA-Z0-9]+;)"#).unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Extract a finding from captures
    /// It is used to avoid duplicating this for each regex.
    fn extract_finding_from_captures(
        &self,
        captures: Captures,
        url_response: &UrlResponse,
    ) -> Finding {
        let mut evidence = captures["wholematch"].to_string();
        let evidence_length = evidence.len();
        if evidence_length > 100 {
            let evidencep1 = evidence[0..30].to_string();
            let evidencep2 = evidence[evidence_length - 30..].to_string();
            evidence = format!("{}[...]{}", evidencep1, evidencep2);
        }

        let version = captures["version"].to_string();
        // Add a space in the version, so in the evidence text we
        // avoid a double space if the version is not found
        let version_text = format!(" {}", version);

        let evidence_text = format!(
                    "Handlebars{} has been identified because we found \"{}\" at this url: {}",
                    version_text,
                    evidence,
                    url_response.url
                );

        return Finding::new(
            "Handlebars",
            Some(&version),
            &evidence,
            &evidence_text,
            Some(&url_response.url),
        );
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response));
        }

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response));
        }
        None
    }
}

impl<'a> HttpChecker for HandlebarsChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        for url_response in data {
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Handlebars
    }
}
