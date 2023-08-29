//! The phpMyAdmin checker.
//! This module contains the checker used to determine if phpMyAdmin is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct PhpMyAdminChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PhpMyAdminChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Note: the checker doesn't look in the HTML code of the main page
        // for ?v=5.2.0
        // It's often removed, and seems not needed yet.
        let mut regexes = HashMap::new();
        // Example: <title>Welcome to phpMyAdmin’s documentation! &#8212; phpMyAdmin 4.4.15.10 documentation</title>
        let documentation_regex = Regex::new(r"<title>Welcome to phpMyAdmin.+(?P<wholematch>phpMyAdmin (?P<version>\d+\.\d+\.\d+(\.\d+)?)) documentation</title>").unwrap();
        // Example: 5.2.0 (2022-05-10)
        // The first version encountered in the ChangeLog is the latest
        let changelog_regex = Regex::new(
            r"^(?P<wholematch>(?P<version>\d+\.\d+\.\d+(\.\d+)?) \(\d\d\d\d-\d\d-\d\d\))",
        )
        .unwrap();
        regexes.insert("http-body-documentation", documentation_regex);
        regexes.insert("http-body-changelog", changelog_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running phpMyAdminChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-documentation")
            .expect("Regex \"http-body-documentation\" not found.")
            .captures(&url_response.body);
        // The regex matches
        if caps_result.is_some() {
            info!("Regex phpMyAdmin/http-body-documentation matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "phpMyAdmin", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        // This regex is not restrictive and could generate false positive
        // results, so restrict its usage on URLs containing /ChangeLog
        if url_response.url.contains("/ChangeLog") {
            let caps_result = self
                .regexes
                .get("http-body-changelog")
                .expect("Regex \"http-body-changelog\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex phpMyAdmin/http-body-changelog matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "phpMyAdmin", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }

        None
    }
}

impl<'a> HttpChecker for PhpMyAdminChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running PhpMyAdminChecker::check_http()");

        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return vec![response.unwrap()];
            }
        }
        return Vec::new();
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::PhpMyAdmin
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = PhpMyAdminChecker::new();
        let body1 = r#"<title>Welcome to phpMyAdmin's documentation! phpMyAdmin 5.2.0 documentation</title>"#;
        let url1 = "https://www.example.com/phpmyadmin/doc/html/index.html";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "phpMyAdmin 5.2.0",
            "phpMyAdmin",
            Some("5.2.0"),
            Some(url1),
        );

        let body2 = r#"5.2.0 (2022-05-10)"#;
        let url2 = "https://www.example.com/phpmyadmin/ChangeLog";
        url_response_valid.body = body2.to_string();
        url_response_valid.url = url2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "5.2.0 (2022-05-10)",
            "phpMyAdmin",
            Some("5.2.0"),
            Some(url2),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = PhpMyAdminChecker::new();
        let body = r#"<h1>phpMyAdmin 5.2</h1>"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/about.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = PhpMyAdminChecker::new();
        let body1 = r#"<title>Welcome to phpMyAdmin's documentation! phpMyAdmin 5.2.1 documentation</title>"#;
        let url1 = "https://www.example.com/mysql/doc/html/index.html";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "phpMyAdmin 5.2.1",
            "phpMyAdmin",
            Some("5.2.1"),
            Some(url1),
        );

        let body2 = "5.2.1 (2022-05-11)";
        let url2 = "https://www.example.com/mysql/ChangeLog";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "5.2.1 (2022-05-11)",
            "phpMyAdmin",
            Some("5.2.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = PhpMyAdminChecker::new();
        let body1 = r#"About PhpMyAdmin 8.2.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "5.2.0 (2022-05-10)";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/NotChangeLog",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
