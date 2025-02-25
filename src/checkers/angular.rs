//! The Angular (2+) checker.
//! This module contains the checker used to determine if Angular is
//! used by the asset.
//! https://angular.dev/

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> AngularChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: CORE="@angular/core"[...]var VERSION2 = new Version("15.2.4")
        let source_code_regex = Regex::new(
            r#"(?P<wholematch>CORE=['"]@angular\/.+['"].+new\s+Version\(['"](?P<version1>\d+\.\d+\.\d+)['"]\))"#,
        )
        .unwrap();

        regexes.insert("http-body-source", (source_code_regex, 15, 21));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Angular/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                    Some(url_response),
                    keep_left.to_owned(),
                    keep_right.to_owned(),
                    Technology::Angular,
                    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for AngularChecker<'a> {}

impl<'a> HttpChecker for AngularChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running AngularChecker::check_http()");
        let mut findings = Vec::new();
        for url_response in data {
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                findings.push(response.unwrap());
            }
        }
        return findings;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Angular
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = AngularChecker::new();
        let body1 =
            r#"var a = 2;CORE="@angular/core";var b = new Version("16.1.8"); var c = 'test';"#;
        let url1 = "https://www.example.com/js/angular.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Version(\"16.1.8\")",
            Technology::Angular,
            Some("16.1.8"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = AngularChecker::new();
        let body = r#"var a = 2;package="angular";var b = new Version("16.1.8"); var c = 'test';"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
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
        let checker = AngularChecker::new();
        let body1 =
            r#"var a = 2;CORE="@angular/core";var b = new Version("16.1.8"); var c = 'test';"#;
        let url1 = "https://www.example.com/a.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to see in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "Version(\"16.1.8\")",
            Technology::Angular,
            Some("16.1.8"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = AngularChecker::new();
        let body1 = r#"var a = 2;CORE="angular";var b = new Version("16.1.8"); var c = 'test';"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"var a = 2;code="Angular";var b = new version("16.1.8"); var c = 'test';"#;
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
