//! The SquirrelMail checker.
//! This module contains the checker used to determine if SquirrelMail is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct SquirrelMailChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> SquirrelMailChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <small>SquirrelMail wersja 1.4.15<br />
        // Note: the word "version" between SquirrelMail and the version is translated
        // on each instance, so it's better to allow any word chars.
        let source_code_regex = Regex::new(r"<small>(?P<wholematch>SquirrelMail\s+\w+\s+(?P<version1>\d+\.\d+\.\d+(\.\d+)?))\s*<br\s*/?>").unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running SquirrelMailChecker::check_http_body() on {}",
            url_response.url
        );

        // This regex is not restrictive and could generate false positive
        // results, so restrict its usage on URLs containing /src/login.php
        if url_response.url.contains("/src/login.php") {
            let caps_result = self
                .regexes
                .get("http-body-source")
                .expect("Regex \"http-body-source\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex SquirrelMail/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                    caps,
                    url_response,
                    30,
                    30,
                    "SquirrelMail",
                    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
                ));
            }
        }

        None
    }
}

impl<'a> HttpChecker for SquirrelMailChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running SquirrelMailChecker::check_http()");

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
        Technology::SquirrelMail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = SquirrelMailChecker::new();
        let body1 = r#"<small>SquirrelMail version 1.4.15<br />"#;
        let url1 = "https://www.example.com/squirrelmail/src/login.php";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "SquirrelMail version 1.4.15",
            "SquirrelMail",
            Some("1.4.15"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = SquirrelMailChecker::new();
        let body = r#"<h1>SquirrelMail 1.5.2</h1>"#;
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
        let checker = SquirrelMailChecker::new();
        let body1 = r#"<small>SquirrelMail wersja 1.4.14<br/>"#;
        let url1 = "https://www.example.com/src/login.php";
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
            "SquirrelMail wersja 1.4.14",
            "SquirrelMail",
            Some("1.4.14"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = SquirrelMailChecker::new();
        let body1 = r#"About SquirrelMail 8.2.11"#;
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
