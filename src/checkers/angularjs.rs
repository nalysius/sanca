//! The AngularJS (1.x) checker.
//! This module contains the checker used to determine if AngularJS is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularJSChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> AngularJSChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /**
        //           * @license AngularJS v1.8.2
        //
        // or
        //
        // /*
        //  * AngularJS v1.8.2
        //
        // Note: (?m) enables multi line mode. So, ^ marks the beginning of the line, not
        // the beginning of the whole input
        let comment_regex = Regex::new(
            r"(?m)^\s+(\*\s+)?(?P<wholematch>(@license\s+)?AngularJS\s+v(?P<version>\d+\.\d+\.\d+))"
        )
        .unwrap();

        // Example: ] http://errors.angularjs.org/1.8.2/
        // 'https://errors.angularjs.org/1.8.2/'
        let body_minified_regex =
            Regex::new(r#"(\] |'|\\n)(?P<wholematch>https?:\/\/errors.angularjs.org\/(?P<version>\d+\.\d+\.\d+)\/)"#)
                .unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularJSChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AngularJS/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "AngularJS", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AngularJS/http-body-minified matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 30, "AngularJS", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for AngularJSChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
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
        Technology::AngularJS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = AngularJSChecker::new();
        let body = r#"a.test();var errorPage = 'https://errors.angularjs.org/1.8.2/';"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/js/file.js",
            HashMap::new(),
            body,
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_matches() {
        let checker = AngularJSChecker::new();
        let body = r#"var notAngularjs = "The URL is http://errors.angularjs.org/1.8.2";"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_none());
    }

    #[test]
    fn comment_matches() {
        let checker = AngularJSChecker::new();
        let body1 = r#" * @license AngularJS v1.8.2"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = " AngularJS v1.5.3 ";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn comment_doesnt_matches() {
        let checker = AngularJSChecker::new();
        let body1 = r#"license AngularJS v1.8.2"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_none());

        let body2 = "AngularJS 1.5.3";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = AngularJSChecker::new();
        let body1 = r#"var a = "\nhttp://errors.angularjs.org/1.9.3/";"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/a.js",
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

        let body2 = " * @license AngularJS v1.5.3";
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/a.js",
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
        let checker = AngularJSChecker::new();
        let body1 = r#"<p>You can find errors.angularjs.org 1.8.3</p>"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let body2 = r#"<a href="http://errors.angularjs.org/1.5.8">Click Me</a>"#;
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
        let checker = AngularJSChecker::new();
        let body1 = r#"var a = "\nhttp://errors.angularjs.org/1.9.3/";"#;
        let url = "https://www.example.com/a.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "http://errors.angularjs.org/1.9.3/";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("AngularJS", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("1.9.3", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("AngularJS 1.9.3")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
