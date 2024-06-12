//! The LayerSlider checker.
//! This module contains the checker used to determine if LayerSlider is
//! used by the asset.
//! https://layerslider.com/

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct LayerSliderChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> LayerSliderChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: {},ie.1O={2H:{}},ie.5q={6s:"6.8.4",kd:"ua",km:"ub. e0. 13."}
        let source_regex = Regex::new(
            r#"(?P<wholematch>[a-zA-Z0-9]+\s*:\s*['"](?P<version1>\d+\.\d+\.\d+(\.\d+)?)['"])"#,
        )
        .unwrap();

        regexes.insert("http-body-source", (source_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running LayerSliderChecker::check_http_body() on {}",
            url_response.url
        );

        // Search only in this file
        if !url_response
            .url
            .contains("layerslider.kreaturamedia.jquery.js")
        {
            return None;
        }

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex LayerSlider/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                    caps,
                    Some(url_response),
                    keep_left.to_owned(),
                    keep_right.to_owned(),
                    "LayerSlider",
                    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for LayerSliderChecker<'a> {}

impl<'a> HttpChecker for LayerSliderChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running LayerSliderChecker::check_http()");
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
        Technology::WPPLayerSlider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = LayerSliderChecker::new();
        let body1 = r#"{},ie.1O={2H:{}},ie.5q={6s:"6.8.4",kd:"ua",km:"ub. e0. 13."}"#;
        let url1 = "https://www.example.com/blog/wp-content/plugins/LayerSlider/static/layerslider/js/layerslider.kreaturamedia.jquery.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "6s:\"6.8.4\"",
            "LayerSlider",
            Some("6.8.4"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = LayerSliderChecker::new();
        let body = r#"var slider = {version:"6", kd:"ua",km:"ub. e0. 13."}"#;
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
        let checker = LayerSliderChecker::new();
        let body1 = r#"{},ie.1O={2H:{}},ie.5q={ version : '7.8.4' , kd:"ua",km:"ub. e0. 13."}"#;
        let url1 = "https://www.example.com/wp-content/plugins/LayerSlider/static/layerslider/js/layerslider.kreaturamedia.jquery.js";
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
            "version : '7.8.4'",
            "LayerSlider",
            Some("7.8.4"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = LayerSliderChecker::new();
        let body1 =
            r#"Meta: &lt;meta name="generator" content="Powered by Layer Slider 6.8.11." /&gt;"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install Layer Slider 6.9.10"#;
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
