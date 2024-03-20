//! The Prestashop checker.
//! This module contains the checker used to determine if Prestashop is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct PrestashopChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PrestashopChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: Release Notes for PrestaShop 1.7
        //
        // #   v1.7.8.7 - (2022-07-20)
        //
        // The first version encountered in the ChangeLog is the latest
        let changelog_regex = Regex::new(
            r"(?s).+Release\s+Notes\s+for\s+PrestaShop\s+\d\.\d..####################################.#\s+(?P<wholematch>v(?P<version>\d+\.\d+\.\d+(\.\d+)?)\s+-\s+\(\d\d\d\d-\d\d-\d\d\))",
        )
        .unwrap();
        regexes.insert("http-body-changelog", changelog_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PrestashopChecker::check_http_body() on {}",
            url_response.url
        );

        // This regex is not restrictive and could generate false positive
        // results, so restrict its usage on URLs containing /docs/CHANGELOG.txt
        if url_response.url.contains("/docs/CHANGELOG.txt") {
            let caps_result = self
                .regexes
                .get("http-body-changelog")
                .expect("Regex \"http-body-changelog\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Prestashop/http-body-changelog matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "Prestashop", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }

        None
    }
}

impl<'a> HttpChecker for PrestashopChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running PrestashopChecker::check_http()");

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
        Technology::Prestashop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = PrestashopChecker::new();
        let body1 = r#"Release Notes for PrestaShop 1.7\n\n#   1.7.3 - (2022-05-10)"#;
        let url1 = "https://www.example.com/docs/CHANGELOG.txt";
        url_response_valid.body = body1.to_string();
        url_response_valid.url = url1.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "1.7.3 - (2022-05-10)",
            "Prestashop",
            Some("1.7.3"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = PrestashopChecker::new();
        let body = r#"<h1>Prestashop 1.6</h1>"#;
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
        let checker = PrestashopChecker::new();
        let body1 = "Release Notes for PrestaShop 1.6\n\n#   v1.6.4.1 - (2020-05-17)";
        let url1 = "https://www.example.com/shop/docs/mysql/ChangeLog";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
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
            "1.6.4.1 (2020-05-17)",
            "Prestashop",
            Some("1.6.4.1"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = PrestashopChecker::new();
        let body1 = r#"About Prestashop 1.8.2.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "# 1.6.3.8 - (2022-05-10)";
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
