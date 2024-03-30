//! The Phone System 3CX checker.
//! This module contains the checker used to determine if Phone System 3CX is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct PhoneSystem3CXChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PhoneSystem3CXChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: name: "Webclient",version: "18.0.9.20"
        let comment_regex = Regex::new(r#".+(?P<wholematch>name\s*:\s*['"]Webclient['"]\s*,.*version\s*:\s*['"](?P<version1>\d+\.\d+\.\d+\.\d+)['"])"#).unwrap();
        regexes.insert("http-body-comment", comment_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PhoneSystem3CXChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex PhoneSystem3CX/http-body-comment matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, Some(url_response), 30, 30, "3CXPhoneSystem", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> Checker for PhoneSystem3CXChecker<'a> {}

impl<'a> HttpChecker for PhoneSystem3CXChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running PhoneSystem3CXChecker::check_http()");
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
        Technology::PhoneSystem3CX
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_matches() {
        let checker = PhoneSystem3CXChecker::new();
        let body1 = r#"var a = {name:"Webclient",version: "18.0.9.20"}"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version: \"18.0.9.20\"",
            "3CXPhoneSystem",
            Some("18.0.9.20"),
            Some(url1),
        );

        let body2 = r#"{ name:'Webclient',version:'18.0.8.17'"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version:'18.0.8.17'",
            "3CXPhoneSystem",
            Some("18.0.8.17"),
            Some(url1),
        );
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = PhoneSystem3CXChecker::new();
        let body1 = r#"Webclient: "18.0.9.20""#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = r#"name: "webClient",Version: "18.0.9.20""#;
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = PhoneSystem3CXChecker::new();
        let body1 = r#"{name : 'Webclient',version : '18.1.2.3'"#;
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
            "version : '18.1.2.3'",
            "3CXPhoneSystem",
            Some("18.1.2.3"),
            Some(url1),
        );

        let body2 = r#"{name: "Webclient", version : '18.1.4.3'"#;
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
            "version : '18.1.4.3'",
            "3CXPhoneSystem",
            Some("18.1.4.3"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = PhoneSystem3CXChecker::new();
        let body1 = r#"var name= "Webclient"; var version = "18.0.9.20""#;
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
