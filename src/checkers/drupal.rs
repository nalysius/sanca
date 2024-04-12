//! The Drupal checker.
//! This module contains the checker used to determine if Drupal is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct DrupalChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> DrupalChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />
        let body_meta_regex = Regex::new(r#"(?P<wholematch><meta\s+name\s*=\s*['"][Gg]enerator['"]\s+content\s*=\s*['"]Drupal\s+(?P<version1>\d+(\.\d+)?)( \(https://www.drupal.org\))?['"]\s*\/>)"#).unwrap();
        regexes.insert("http-body-meta", (body_meta_regex, 50, 50));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running DrupalChecker::check_http_body() on {}",
            url_response.url
        );
        let body_meta_regex_params = self
            .regexes
            .get("http-body-meta")
            .expect("Regex Drupal/http-body-meta not found");
        let (regex_meta, keep_left_meta, keep_right_meta) = body_meta_regex_params;
        let caps_result = regex_meta.captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Drupal/http-body-meta matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
		caps,
		Some(url_response),
		keep_left_meta.to_owned(),
		keep_right_meta.to_owned(),
		"Drupal",
		"$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
	    ));
        }
        None
    }
}

impl<'a> Checker for DrupalChecker<'a> {}

impl<'a> HttpChecker for DrupalChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running DrupalChecker::check_http()");

        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            //
            // Handle only the 200 status code, to avoid false positive on 404
            if url_response.request_type != UrlRequestType::Default
                || url_response.status_code != 200
            {
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
        Technology::Drupal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = DrupalChecker::new();
        let body1 = r#"<meta name="generator" content="Drupal 8 (https://www.drupal.org)" />"#;
        let url1 = "https://www.example.com/index.php";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Drupal 8",
            "Drupal",
            Some("8"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = DrupalChecker::new();
        let body = r#"<meta name="Generator" content="WordPress" /><h1>About Drupal 9</h1>"#;
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
        let checker = DrupalChecker::new();
        let body1 = r#"<meta   name = "generator"     content = "Drupal 9"/>"#;
        let url1 = "https://www.example.com/blog.php";
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
            "content = \"Drupal 9\"",
            "Drupal",
            Some("9"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = DrupalChecker::new();
        let body1 = r#"About Drupal 6"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "src='/wp.js?ver=5.4.3'";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/not-wp-login.php",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
