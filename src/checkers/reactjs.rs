//! The ReactJS checker.
//! This module contains the checker used to determine if ReactJS is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct ReactJSChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ReactJSChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: var ReactVersion = '18.2.0';
        let source_code_regex = Regex::new(
            r#"\s*(?P<wholematch>var\s+ReactVersion\s*=\s*['"](?P<version>\d+\.\d+(\.\d+)?)['"])"#,
        )
        .unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ReactJSChecker::check_http_body() on {}",
            url_response.url
        );

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex ReactJS/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                10,
                20,
                "ReactJS",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> HttpChecker for ReactJSChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running ReactJSChecker::check_http()");
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
        Technology::ReactJS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = ReactJSChecker::new();
        let body1 = r#"var ReactVersion = "18.2.0";var b = 1;"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "ReactVersion = \"18.2.0\"",
            "ReactJS",
            Some("18.2.0"),
            Some(url1),
        );

        let body2 = r#" var ReactVersion='18.1.2'"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "ReactVersion='18.1.2'",
            "ReactJS",
            Some("18.1.2"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = ReactJSChecker::new();
        let body = r#"var f = "ReactVersion"; VERSION="18.1.1";"#;
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
        let checker = ReactJSChecker::new();
        let body1 = r#"var ReactVersion = "18.2.10";"#;
        let url1 = "https://www.example.com/r.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "ReactVersion = \"18.2.10\"",
            "ReactJS",
            Some("18.2.10"),
            Some(url1),
        );

        let body2 = r#" var ReactVersion="18.1.1";"#;
        let url2 = "https://www.example.com/r.js";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::JavaScript);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let findings = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "ReactVersion=\"18.1.1\"",
            "ReactJS",
            Some("18.1.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = ReactJSChecker::new();
        let body1 = r#"React 18.2.15 is not installed here."#;
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
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
