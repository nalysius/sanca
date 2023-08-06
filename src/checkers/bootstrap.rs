//! The Bootstrap checker.
//! This module contains the checker used to determine if Bootstrap is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct BootstrapChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> BootstrapChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*!
        //           * Bootstrap v5.2.3 (https://getbootstrap.com/)
        let comment_regex = Regex::new(
            r"\s*\*\s*(?P<wholematch>Bootstrap v(?P<version>\d+\.\d+\.\d+))\s+\(https?:\/\/getbootstrap.com\/?\)",
        )
        .unwrap();

        // Example: Bootstrap[...]VERSION(){return"5.2.3"}
        //
        // or
        //
        // Bootstrap[...]d.VERSION="3.3.7"
        let source_code_regex = Regex::new(
            r#"(?P<wholematch>Bootstrap.+VERSION(\(\)\s*\{\s*return\s*"|=")(?P<version>\d+\.\d+\.\d+)")"#,
        )
        .unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running BootstrapChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Bootstrap/http-body-comment matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                40,
                40,
                "Bootstrap",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Bootstrap/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                10,
                20,
                "Bootstrap",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> HttpChecker for BootstrapChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running BootstrapChecker::check_http()");
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
        Technology::Bootstrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = BootstrapChecker::new();
        let body1 = r#"Bootstrap.this();i.VERSION="3.3.7";"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/js/file.js",
            HashMap::new(),
            body1,
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = r#"Bootstrap.this();i.VERSION(){return"3.3.7";}"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_matches() {
        let checker = BootstrapChecker::new();
        let body = r#"application.bootstrap(); application.VERSION = "1.2.3";"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn comment_matches() {
        let checker = BootstrapChecker::new();
        let body1 = r#" * Bootstrap v5.2.0 (https://getbootstrap.com/)"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = "* Bootstrap v5.2.0 (http://getbootstrap.com)";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn comment_doesnt_matches() {
        let checker = BootstrapChecker::new();
        let body1 = r#"// Bootstrap 3.2.1 (https://getbootstrap.com)"#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = " * Bootstrap v3.2.1";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = BootstrapChecker::new();
        let body1 = r#"* Bootstrap v5.3.0 (https://getbootstrap.com/)"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/a.js",
            HashMap::new(),
            body1,
            UrlRequestType::JavaScript,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert!(finding.is_some());

        let body2 = "* Bootstrap v5.3.0 (http://getbootstrap.com)";
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/a.js",
            HashMap::new(),
            body2,
            UrlRequestType::JavaScript,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert!(finding.is_some());
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = BootstrapChecker::new();
        let body1 = r#"Bootstrap v5.3.0 is available at https://getbootstrap.com"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let body2 = r#"Bootstrap doesn't match here."#;
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_fields_are_valid() {
        let checker = BootstrapChecker::new();
        let body1 = "* Bootstrap v5.3.0 (http://getbootstrap.com)";
        let url = "https://www.example.com/b.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "Bootstrap v5.3.0";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("Bootstrap", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("5.3.0", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("Bootstrap 5.3.0")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
