//! The Plesk checker.
//! This module contains the checker used to determine if Plesk is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct PleskChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PleskChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <title>Plesk Obsidian 17.1.36</title>
        let login_regex = Regex::new(
            r"<title>(?P<wholematch>Plesk\s+[a-zA-Z0-9]+\s+(?P<version>\d+\.\d+\.\d+))</title>",
        )
        .unwrap();
        regexes.insert("http-body-login", login_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PleskChecker::check_http_body() on {}",
            url_response.url
        );

        // Restrict the verification on the login page
        if url_response.url.contains("/login_up.php") {
            let caps_result = self
                .regexes
                .get("http-body-login")
                .expect("Regex \"http-body-login\" not found.")
                .captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Plesk/http-body-documentation matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "Plesk", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }

        None
    }
}

impl<'a> HttpChecker for PleskChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running PleskChecker::check_http()");

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
        Technology::Plesk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = PleskChecker::new();
        let body1 = r#"<title>Plesk Obsidian 18.1.36</title>"#;
        let url1 = "http://www.example.com:8080/login_up.php?this=that";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Plesk Obsidian 18.1.36",
            "Plesk",
            Some("18.1.36"),
            Some(url1),
        );

        let body2 = r#"<title>Plesk Onyx 17.1.36</title>"#;
        let url2 = "https://www.example.com:8443/login_up.php";
        url_response_valid.body = body2.to_string();
        url_response_valid.url = url2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Plesk Onyx 17.1.36",
            "Plesk",
            Some("17.1.36"),
            Some(url2),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = PleskChecker::new();
        let body = r#"<h1>Plesk 17.2</h1>"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/about.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
            200
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = PleskChecker::new();
        let body1 = r#"<title>Plesk Obsidian 18.2.42</title>"#;
        let url1 = "https://www.example.com:8443/login_up.php";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "Plesk Obsidian 18.2.42",
            "Plesk",
            Some("18.2.42"),
            Some(url1),
        );

        let body2 = "<title>Plesk Onyx 17.42.1</title>";
        let url2 = "http://www.example.com:8080/login_up.php";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200
        );
        let findings = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "Plesk Onyx 17.42.1",
            "Plesk",
            Some("17.42.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = PleskChecker::new();
        let body1 = r#"About Plesk 17.2.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200
        );

        let body2 = "<title>Plesk Obsidian 18.3.2</title>";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/not-login_up.php",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
