//! The jQuery checker.
//! This module contains the checker used to determine if jQuery is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct JQueryChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> JQueryChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*!
        //           *jQuery JavaScript Library v3.7.0
        //
        // or
        //
        // /*! jQuery v3.7.0 |
        let comment_regex = Regex::new(r"\/\*![\s\*]+(?P<wholematch>jQuery (JavaScript Library )?(v(?P<version>\d\.\d\.\d)))( |)?").unwrap();
        regexes.insert("http-body-comment", comment_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running JQueryChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex JQuery/http-body-comment matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "jQuery", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for JQueryChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running JQueryChecker::check_http()");
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
        Technology::JQuery
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;

    #[test]
    fn comment_matches() {
        let checker = JQueryChecker::new();
        let body1 = r#"/*! jQuery v3.7.0 | 2023"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = "/*!
        * jQuery JavaScript Library v3.7.0";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = JQueryChecker::new();
        let body1 = r#"/**
        * jQuery 1.2.3
        "#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = "// jQuery v2";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = JQueryChecker::new();
        let body1 = r#"/*!
        *
        *jQuery v4.7.7"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/j.js",
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

        let body2 = "/*! * jQuery v3.6.1 | 2022";
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/g.js",
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
        let checker = JQueryChecker::new();
        let body1 = r#"jQuery v3.7.0 is not installed here."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let body2 = r#"It should not be detected"#;
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
        let checker = JQueryChecker::new();
        let body1 = r#"/*! *jQuery v3.7.0 | 2023"#;
        let url = "https://www.example.com/g.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "jQuery v3.7.0";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("jQuery", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("3.7.0", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("jQuery 3.7.0")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
