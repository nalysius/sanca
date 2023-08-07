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
            r#"(?P<wholematch>"typo3\/cms-core" *: *"(?P<version>\d+\.\d+\.\d+(\.\d+)?)")"#,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = Typo3Checker::new();
        let body1 = r#""typo3/cms-core": "4.7.1""#;
        let url_response_valid = UrlResponse::new(
            "http://www.example.com/typo3/composer.json",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = Typo3Checker::new();
        let body = r#"typo3/cms-core: 3.2.1"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/about.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = Typo3Checker::new();
        let body1 = r#""typo3/cms-core" : "4.7.2.8""#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/site/typo3/composer.json",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert!(finding.is_some());
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = Typo3Checker::new();
        let body1 = r#"About TYPO3 4.7.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );

        let body2 = "<h3>TYPO3/4.3.2</h3>";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/not-404-page",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_fields_are_valid() {
        let checker = Typo3Checker::new();
        let body1 = r#""typo3/cms-core": "4.7.8""#;
        let url = "https://www.example.com/typo3/install/composer.json";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::Default);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "\"4.7.8";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("TYPO3", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("4.7.8", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("TYPO3 4.7.8")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
