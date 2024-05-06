//! The Elementor checker.
//! This module contains the checker used to determine if Elementor is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct ElementorChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> ElementorChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: Stable tag: 3.7.8
        let readme_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version1>\d+\.\d+(\.\d+)?))"#).unwrap();

        let source_code_regex = Regex::new(
            r#"(?P<wholematch><meta\s+name\s*=\s*['"][Gg]enerator['"]\s+content\s*=\s*['"]Elementor\s+(?P<version1>\d+\.\d+(\.\d+)?))"#,
        )
        .unwrap();

        regexes.insert("http-body-readme", (readme_regex, 30, 30));
        regexes.insert("http-body-source", (source_code_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ElementorChecker::check_http_body() on {}",
            url_response.url
        );

        let body_regex_params = self
            .regexes
            .get("http-body-source")
            .expect("Regex Elementor/http-body-source not found");
        let (regex, keep_left, keep_right) = body_regex_params;
        let caps_result = regex.captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Elementor/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left.to_owned(),
                keep_right.to_owned(),
                "Elementor",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
	    ));
        }

        if url_response
            .url
            .contains("/wp-content/plugins/elementor/readme.txt")
        {
            let body_regex_params = self
                .regexes
                .get("http-body-readme")
                .expect("Regex Elementor/http-body-readme not found");
            let (regex, keep_left, keep_right) = body_regex_params;
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Elementor/http-body-readme matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left.to_owned(),
                keep_right.to_owned(),
                "Elementor",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }
        None
    }
}

impl<'a> Checker for ElementorChecker<'a> {}

impl<'a> HttpChecker for ElementorChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running ElementorChecker::check_http()");
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
        Technology::WPPElementor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = ElementorChecker::new();
        let body1 = r#"=== Elementor Website Builder ===
        Contributors: elemntor
        Tags: page builder, editor, landing page, drag-and-drop, elementor, visual editor, wysiwyg, design, maintenance mode, coming soon, under construction, website builder, landing page builder, front-end builder
        Requires at least: 5.0
        Tested up to: 6.0
        Requires PHP: 7.0
        Stable tag: 3.7.8"#;
        let url1 = "https://www.example.com/blog/wp-content/plugins/elementor/readme.txt";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 3.7.8",
            "Elementor",
            Some("3.7.8"),
            Some(url1),
        );

        let body2 = r#" <meta name="generator" content="Elementor 3.21.4; features: e_optimized_assets_loading"#;
        let url2 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Elementor 3.21.4",
            "Elementor",
            Some("3.21.4"),
            Some(url2),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = ElementorChecker::new();
        let body = r#"Elementor can be found in stable tag: 3.7.8"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/wp-content/plugins/other-plugin/readme.txt",
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
        let checker = ElementorChecker::new();
        let body1 = r#"=== Elementor Website Builder ===
        Contributors: elemntor
        Tags: page builder, editor, landing page, drag-and-drop, elementor, visual editor, wysiwyg, design, maintenance mode, coming soon, under construction, website builder, landing page builder, front-end builder
        Requires at least: 5.0
        Tested up to: 6.0
        Requires PHP: 7.0
        Stable tag: 3.7.7"#;
        let url1 = "https://www.example.com/wp-content/plugins/elementor/readme.txt";
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
            "Stable tag: 3.7.7",
            "Elementor",
            Some("3.7.7"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = ElementorChecker::new();
        let body1 = r#"=== Another plugin ===
        Contributors: takayukister
        Donate link: https://anotherplugin.com/donate/
        Tags: contact, form, contact form, feedback, email, ajax, captcha, akismet, multilingual
        Requires at least: 6.2
        Requires PHP: 7.4
        Tested up to: 6.4
        Stable tag: 5.1.4"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install Elementor 5.2.4"#;
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
