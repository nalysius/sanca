//! The TYPO3 checker.
//! This module contains the checker used to determine if TYPO3 is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct Typo3Checker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> Typo3Checker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: "typo3/cms-core": "x.y.z"
        let composer_regex = Regex::new(
            r#"(?P<wholematch>"typo3\/cms-core": *"(?P<version>\d+\.\d+\.\d+(\.\d+)?)")"#,
        )
        .unwrap();
        regexes.insert("http-body-composer", composer_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running Typo3Checker::check_http_body() on {}",
            url_response.url
        );

        // This regex is not restrictive and could generate false positive
        // results, so restrict its usage on URLs containing composer.json
        if url_response.url.contains("/composer.json") {
            let caps_result = self
                .regexes
                .get("http-body-composer")
                .expect("Regex \"http-body-composer\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex TYPO3/http-body-composer matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "TYPO3", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }

        None
    }
}

impl<'a> HttpChecker for Typo3Checker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running Typo3Checker::check_http()");
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Typo3
    }
}
