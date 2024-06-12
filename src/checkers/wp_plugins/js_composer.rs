//! The JSComposer checker.
//! This module contains the checker used to determine if JSComposer is
//! used by the asset.
//! https://wordpress.org/plugins/visualcomposer/

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct JSComposerChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> JSComposerChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <body class="this that js-comp-ver-6.1 other-class">
        let source_code_regex = Regex::new(
            r#"(?P<wholematch><body\s+[^>]*class\s*=\s*["'][^'"]*js-comp-ver-(?P<version1>\d+\.\d+))[^'"]*["']"#,
        )
        .unwrap();

        regexes.insert("http-body-source", (source_code_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running JSComposerChecker::check_http_body() on {}",
            url_response.url
        );

        let body_regex_params = self
            .regexes
            .get("http-body-source")
            .expect("Regex JSComposer/http-body-source not found");
        let (regex, keep_left, keep_right) = body_regex_params;
        let caps_result = regex.captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex JSComposer/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left.to_owned(),
                keep_right.to_owned(),
                "JSComposer",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> Checker for JSComposerChecker<'a> {}

impl<'a> HttpChecker for JSComposerChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running JSComposerChecker::check_http()");
        let mut findings = Vec::new();
        for url_response in data {
            // Search on the main page only
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                findings.push(response.unwrap());
            }
        }
        return findings;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::WPPJSComposer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = JSComposerChecker::new();
        let body1 = r#"<link rel="stylesheet" href="c.css"/><body class = "home page-template-default_4 js-comp-ver-6.1 p4ge">"#;
        let url1 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "js-comp-ver-6.1",
            "JSComposer",
            Some("6.1"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = JSComposerChecker::new();
        let body = r#"<i>This</i> website is using JSComposer plugin version 6.10"#;
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
        let checker = JSComposerChecker::new();
        let body1 = r#"<link rel="stylesheet" href="c.css"/><body id="app-body" class="home page-template-default_4 js-comp-ver-7.3 p4ge" data-a='b'>"#;
        let url1 = "https://www.example.com/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
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
            "js-comp-ver-7.3",
            "JSComposer",
            Some("7.3"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = JSComposerChecker::new();
        let body1 =
            r#"Marker is &lt;body class = "home page-template-default_4 js-comp-ver-6.1 p4ge"&gt;"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install JSComposer 6.1"#;
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
