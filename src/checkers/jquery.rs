//! The jQuery checker.
//! This module contains the checker used to determine if jQuery is
//! used by the asset.
//! https://jquery.com

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct JQueryChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
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
        let comment_regex = Regex::new(r".*\/\*![\s\*]+(?P<wholematch>jQuery\s+(JavaScript Library )?(v@?(?P<version1>\d+\.\d+\.\d+)))( |)?").unwrap();

        // Example: {jquery:"3.3.1",
        let body_minified_regex =
            Regex::new(r#"\s*(?P<wholematch>jquery\s*:\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#)
                .unwrap();

        // Example: var version = "3.1.1"; var jQuery = {jquery:version,
        let body_minified_regex_alternative =
            Regex::new(r#"(?P<wholematch>(var|let)\s+version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"].+jquery\s*:\s*version)"#).unwrap();
        regexes.insert("http-body-comment", (comment_regex, 30, 30));
        regexes.insert("http-body-minified", (body_minified_regex, 30, 30));
        regexes.insert(
            "http-body-minified-alternative",
            (body_minified_regex_alternative, 30, 30),
        );

        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running JQueryChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex JQuery/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::JQuery,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for JQueryChecker<'a> {}

impl<'a> HttpChecker for JQueryChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running JQueryChecker::check_http()");
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
        Technology::JQuery
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = JQueryChecker::new();
        let body1 = r#"w.prototype={jquery:"3.3.1",constructor:w,length:0"#;
        let url1 = "https://www.example.com/js/file.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "jquery:\"3.3.1\"",
            Technology::JQuery,
            Some("3.3.1"),
            Some(url1),
        );

        let body1 = r#"var version="3.1.1";w.prototype={jquery:version,constructor:w,length:0"#;
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version=\"3.1.1\"",
            Technology::JQuery,
            Some("3.1.1"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = JQueryChecker::new();
        let body = r#"{lodash:"3.3.1","#;
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
    fn comment_matches() {
        let checker = JQueryChecker::new();
        let body1 = r#"/*! jQuery v3.7.0 | 2023"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "jQuery v3.7.0",
            Technology::JQuery,
            Some("3.7.0"),
            Some(url1),
        );

        let body2 = "/*!
        * jQuery JavaScript Library v3.7.0";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "jQuery JavaScript Library v3.7.0",
            Technology::JQuery,
            Some("3.7.0"),
            Some(url1),
        );
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
            200,
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
        *jQuery v3.7.7"#;
        let url1 = "https://www.example.com/j.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
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
            "jQuery v3.7.7",
            Technology::JQuery,
            Some("3.7.7"),
            Some(url1),
        );

        let body2 = "/*! * jQuery v3.6.1 | 2022";
        let url2 = "https://www.example.com/g.js";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::JavaScript, 200);
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
            "jQuery v3.6.1",
            Technology::JQuery,
            Some("3.6.1"),
            Some(url2),
        );
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
            200,
        );
        let body2 = r#"It should not be detected"#;
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
