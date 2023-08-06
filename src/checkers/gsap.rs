//! The GSAP checker.
//! This module contains the checker used to determine if GSAP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct GsapChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> GsapChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*!
        //           * PixiPlugin 3.11.1
        let gsap_plugins = "CSSRulePlugin|CustomEase|Draggable|EaselPlugin|EasePack|Flip|GSAP|MotionPathPlugin|Observer|PixiPlugin|ScrollToPlugin|ScrollTrigger|TextPlugin";
        let comment_regex = Regex::new(&format!(
            r"^\s*\*\s+(?P<wholematch>({})\s+(?P<version>\d+\.\d+\.\d+))",
            gsap_plugins
        ))
        .unwrap();

        // Example: gsap)&&f.r[...],i,c,y,v,h,r={version:"3.11.1"
        let body_minified_regex =
            Regex::new(r#"(?P<wholematch>gsap.+version[=:]\s*['"](?P<version>\d+\.\d+\.\d+)['"])"#)
                .unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running GsapChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex GSAP/http-body-comment matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "GSAP", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex GSAP/http-body-minified matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 20, "GSAP", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for GsapChecker<'a> {
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
        Technology::Gsap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = GsapChecker::new();
        let body1 = r#"gsap) && a.b = 12;r={version:"3.11.0"};"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/js/file.js",
            HashMap::new(),
            body1,
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = r#"gsap) && a.b = 12;r.version='3.11.0';"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_matches() {
        let checker = GsapChecker::new();
        let body = r#"GSAP is in version 1.2.3"#;
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
    fn comment_matches() {
        let checker = GsapChecker::new();
        let body1 = r#"* Flip 3.11.1"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = " * CustomEase 3.11.1";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn comment_doesnt_matches() {
        let checker = GsapChecker::new();
        let body1 = r#"Is CSSRulePlugin 3.11.1 installed?"#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = "Draggable is not installed.";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = GsapChecker::new();
        let body1 = r#" * ScrollToPlugin    3.1.9"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/g.js",
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

        let body2 = "gsap();var a ='test';version='3.10.4'";
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
        let checker = GsapChecker::new();
        let body1 = r#"GSAP is definitely not installed here."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let body2 = r#"Except if it's installed"#;
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
        let checker = GsapChecker::new();
        let body1 = r#"x.gsap;var var_1= 'test'; version='3.10.5'"#;
        let url = "https://www.example.com/g.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "version='3.10.5'";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("GSAP", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("3.10.5", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("GSAP 3.10.5")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
