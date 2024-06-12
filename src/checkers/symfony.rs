//! The Symfony checker.
//! This module contains the checker used to determine if Symfony is
//! used by the asset.
//! https://symfony.com

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct SymfonyChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> SymfonyChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example:
        // <h2>Symfony Configuration</h2>
        //    <div class="metrics">
        //      <div class="metric">
        //       <span class="value">4.1.21</span>
        //       <span class="label">Symfony version</span>
        //    </div>
        // (?s) means the . character matches also newlines
        let source_code_regex =
            Regex::new(r#"(?s).*<h2>Symfony Configuration</h2>.+(?P<wholematch><span\s+class\s*=\s*['"]value['"]\s*>(?P<version1>\d+\.\d+\.\d+)</span>).+<span class=['"]label['"]>Symfony version</span>"#).unwrap();
        regexes.insert("http-body-source", (source_code_regex, 50, 50));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running SymfonyChecker::check_http_body() on {}",
            url_response.url
        );

        if url_response.url.contains("/_profiler/") {
            let body_regex_params = self
                .regexes
                .get("http-body-source")
                .expect("Regex Symfony/http-body-source not found");
            let (regex, keep_left, keep_right) = body_regex_params;
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Symfony/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "Symfony",
		    "$techno_name$$techno_version$ has been identified because the debug mode was enabled and we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for SymfonyChecker<'a> {}

impl<'a> HttpChecker for SymfonyChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running SymfonyChecker::check_http()");

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
        Technology::Symfony
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = SymfonyChecker::new();
        let body1 = r#" <h2>Symfony Configuration</h2>
            <div class="metrics">
              <div class="metric">
               <span class="value">4.1.2</span>
               <span class="label">Symfony version</span>
            </div>"#;
        let url1 = "https://www.example.com/_profiler/abc123?panel=config";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "<span class=\"value\">4.1.2</span>",
            "Symfony",
            Some("4.1.2"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = SymfonyChecker::new();
        let body = r#"Symfony version 5.1.6"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/",
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
        let checker = SymfonyChecker::new();
        let body1 = r#"<h2>Symfony Configuration</h2>
              <div class='metrics'>
               <div class = "metric">
                <span class='value'>4.1.2</span>
                 <span class="label">Symfony version</span>"#;
        let url1 = "https://www.example.com/app/_profiler/1f3a8c?panel=config";
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
            "<span class='value'>4.1.2</span>",
            "Symfony",
            Some("4.1.2"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = SymfonyChecker::new();
        let body1 = r#"    <span class="sf-value">6.1.23</span>  "#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/invalid/url",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "Symfony version: 6.1.1";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/app/",
            HashMap::new(),
            body2,
            UrlRequestType::JavaScript,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
