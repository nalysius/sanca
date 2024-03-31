//! The ElementsReady Lite checker.
//! This module contains the checker used to determine if ElementsReady Elementor Addons is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct ElementsReadyLiteChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> ElementsReadyLiteChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: Stable tag: 3.7
        let source_code_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version1>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", (source_code_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ElementsReadyLiteChecker::check_http_body() on {}",
            url_response.url
        );

        if url_response
            .url
            .contains("/wp-content/plugins/element-ready-lite/readme.txt")
        {
            let body_regex_params = self
                .regexes
                .get("http-body-source")
                .expect("Regex ElementsReadyLite/http-body-source not found");
            let (regex, keep_left, keep_right) = body_regex_params;
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex ElementsReadyLite/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left.to_owned(),
                keep_right.to_owned(),
                "ElementsReadyLite",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }
        None
    }
}

impl<'a> Checker for ElementsReadyLiteChecker<'a> {}

impl<'a> HttpChecker for ElementsReadyLiteChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running ElementsReadyLiteChecker::check_http()");
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
        Technology::WPPElementsReadyLite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = ElementsReadyLiteChecker::new();
        let body1 = r#"=== ElementsReady Elementor Addons (Elementor Post Grid, Elementor Woocommerce Product Grid, WooCommerce Product Slider, Elementor Templates, Elementor Free Widgets ) ===
        Contributors: QuomodoSoft
        Tags: elementor, elementor addons, elementor widgets, elements, elementor plugins, mega menu, mega menu builder, header footer builder, elements, elementor extensions, elementor modules, page builder addons, addons, essential plugins, essential widgets, elementor pro, free addons, free widgets, free plugins 
        Requires at least: 5.0
        Tested up to: 6.0.2
        Stable tag: 3.7
        Requires PHP: 7.0"#;
        let url1 = "https://www.example.com/blog/wp-content/plugins/element-ready-lite/readme.txt";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 3.7",
            "ElementsReadyLite",
            Some("3.7"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = ElementsReadyLiteChecker::new();
        let body = r#"ElementsReady can be found in stable tag: 3.7.1"#;
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
        let checker = ElementsReadyLiteChecker::new();
        let body1 = r#"=== ElementsReady Elementor Addons (Elementor Post Grid, Elementor Woocommerce Product Grid, WooCommerce Product Slider, Elementor Templates, Elementor Free Widgets ) ===
        Contributors: QuomodoSoft
        Tags: elementor, elementor addons, elementor widgets, elements, elementor plugins, mega menu, mega menu builder, header footer builder, elements, elementor extensions, elementor modules, page builder addons, addons, essential plugins, essential widgets, elementor pro, free addons, free widgets, free plugins 
        Requires at least: 5.0
        Tested up to: 6.0.2
        Stable tag: 3.7
        Requires PHP: 7.0"#;
        let url1 = "https://www.example.com/wp-content/plugins/element-ready-lite/readme.txt";
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
            "Stable tag: 3.7",
            "ElementsReadyLite",
            Some("3.7"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = ElementsReadyLiteChecker::new();
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
        let body2 = r#"How to install ElementsReady 5.2.4"#;
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
