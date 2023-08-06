//! The Angular (2+) checker.
//! This module contains the checker used to determine if Angular is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> AngularChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: CORE="@angular/core"[...]var VERSION2 = new Version("15.2.4")
        let source_code_regex = Regex::new(
            r#"(?P<wholematch>CORE=['"]@angular\/.+['"].+new\s+Version\(['"](?P<version>\d+\.\d+\.\d+)['"]\))"#,
        )
        .unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularChecker::check_http_body() on {}",
            url_response.url
        );

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Angular/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                15,
                21,
                "Angular",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> HttpChecker for AngularChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running AngularChecker::check_http()");
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
        Technology::Angular
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = AngularChecker::new();
        let body =
            r#"var a = 2;CORE="@angular/core";var b = new Version("16.1.8"); var c = 'test';"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/js/angular.js",
            HashMap::new(),
            body,
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
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
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = AngularChecker::new();
        let body =
            r#"var a = 2;CORE="@angular/core";var b = new Version("16.1.8"); var c = 'test';"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/a.js",
            HashMap::new(),
            body,
            UrlRequestType::JavaScript,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to see in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert!(finding.is_some());
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
        );
        let body2 = r#"var a = 2;code="Angular";var b = new version("16.1.8"); var c = 'test';"#;
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
        let checker = AngularChecker::new();
        let body1 =
            r#"var a = 2;CORE="@angular/core";var b = new Version("16.1.8"); var c = 'test';"#;
        let url = "https://www.example.com/aa.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "Version(\"16.1.8\")";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("Angular", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("16.1.8", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("Angular 16.1.8")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
