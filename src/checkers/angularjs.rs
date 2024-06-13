//! The AngularJS (1.x) checker.
//! This module contains the checker used to determine if AngularJS is
//! used by the asset.
//! https://angularjs.org/

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularJSChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
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
            r"(?m)^\s+(\*\s+)?(?P<wholematch>(@license\s+)?AngularJS\s+v(?P<version1>\d+\.\d+\.\d+))"
        )
        .unwrap();

        // Example: ] http://errors.angularjs.org/1.8.2/
        // 'https://errors.angularjs.org/1.8.2/'
        let body_minified_regex =
            Regex::new(r#"(\] |'|\\n|")(?P<wholematch>https?:\/\/errors.angularjs.org\/(?P<version1>\d+\.\d+\.\d+)\/)"#)
                .unwrap();

        // Example: info({angularVersion:"1.8.3"})
        let body_minified_regex_alternative = Regex::new(
            r#"(?P<wholematch>angularVersion\s*:\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#,
        )
        .unwrap();

        regexes.insert("http-body-comment", (comment_regex, 30, 30));
        regexes.insert("http-body-minified", (body_minified_regex, 10, 30));
        regexes.insert(
            "http-body-minified-alternative",
            (body_minified_regex_alternative, 15, 15),
        );

        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularJSChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex AngularJS/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::AngularJS,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for AngularJSChecker<'a> {}

impl<'a> HttpChecker for AngularJSChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
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
        Technology::AngularJS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = AngularJSChecker::new();
        let body = r#"a.test();var errorPage = 'https://errors.angularjs.org/1.8.2/';"#;
        let url1 = "https://www.example.com/js/file.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "https://errors.angularjs.org/1.8.2",
            Technology::AngularJS,
            Some("1.8.2"),
            Some(url1),
        );

        let body2 = r#"info({angularVersion: "1.8.3"})"#;
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body2, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "angularVersion: \"1.8.3\"",
            Technology::AngularJS,
            Some("1.8.3"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = AngularJSChecker::new();
        let body = r#"var notAngularjs = "The URL is http://errors.angularjs.org/1.8.2";"#;
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
        let checker = AngularJSChecker::new();
        let body1 = r#" * @license AngularJS v1.8.2"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "AngularJS v1.8.2",
            Technology::AngularJS,
            Some("1.8.2"),
            Some(url1),
        );

        let body2 = " AngularJS v1.5.3 ";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "AngularJS v1.5.3",
            Technology::AngularJS,
            Some("1.5.3"),
            Some(url1),
        );
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = AngularJSChecker::new();
        let body1 = r#"license AngularJS v1.8.2"#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = "AngularJS 1.5.3";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = AngularJSChecker::new();
        let body1 = r#"var a = "\nhttp://errors.angularjs.org/1.9.3/";"#;
        let url1 = "https://www.example.com/a.js";
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
            "http://errors.angularjs.org/1.9.3/",
            Technology::AngularJS,
            Some("1.9.3"),
            Some(url1),
        );

        let body2 = " * @license AngularJS v1.5.3";
        let url2 = "https://www.example.com/a.js";
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
            "AngularJS v1.5.3",
            Technology::AngularJS,
            Some("1.5.3"),
            Some(url2),
        );
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
            200,
        );
        let body2 = r#"<a href="http://errors.angularjs.org/1.5.8">Click Me</a>"#;
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
