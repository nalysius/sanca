//! The WordPress checker.
//! This module contains the checker used to determine if WordPress is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct WordPressChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> WordPressChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <meta name="generator" content="WordPress 6.1.2" />
        let body_meta_regex = Regex::new(r#"(?P<wholematch><meta\s+name\s*=\s*['"]generator['"]\s+content\s*=\s*['"]WordPress (?P<version>\d+\.\d+\.\d+)['"]\s*\/>)"#).unwrap();
        // Example: [...]/style.min.css?ver=6.2.2'
        let body_login_regex =
            Regex::new(r#"(?P<wholematch>\?ver=(?P<version>\d+\.\d+\.\d+))"#).unwrap();
        regexes.insert("http-body-meta", body_meta_regex);
        regexes.insert("http-body-login", body_login_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running WordPressChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-meta")
            .expect("Regex \"http-body-meta\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex WordPress/http-body-meta matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "WordPress", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        // Checking only on the wp-login.php page to avoid false positive
        if url_response.url.contains("/wp-login.php") {
            let caps_result = self
                .regexes
                .get("http-body-login")
                .expect("Regex \"http-body-login\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex WordPress/http-body-login matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "WordPress", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }
        None
    }
}

impl<'a> HttpChecker for WordPressChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running WordPressChecker::check_http()");
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
        Technology::WordPress
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = WordPressChecker::new();
        let body1 = r#"<meta name="generator" content="WordPress 6.1.2" />"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/index.php",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = r#"<link href="style.min.css?ver=6.1.2" rel="stylesheet""#;
        url_response_valid.body = body2.to_string();
        url_response_valid.url = "https://www.example.com/wp-login.php".to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = WordPressChecker::new();
        let body = r#"<h1>WordPress 5.2</h1>"#;
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
        let checker = WordPressChecker::new();
        let body1 = r#"<meta   name = "generator"     content = "WordPress 5.8.4"/>"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/blog.php",
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

        let body2 = "<script src = \"/that.js?ver=5.8.4\"></script>";
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/blog/wp-login.php",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
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
        let checker = WordPressChecker::new();
        let body1 = r#"About WordPress 6.2.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );

        let body2 = "src='/wp.js?ver=5.4.3'";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/not-wp-login.php",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_fields_are_valid() {
        let checker = WordPressChecker::new();
        let body1 = r#"<meta name="generator" content="WordPress 6.1.2"   />"#;
        let url = "https://www.example.com/blog/";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::Default);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "WordPress 6.1.2";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("WordPress", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("6.1.2", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("WordPress 6.1.2")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
