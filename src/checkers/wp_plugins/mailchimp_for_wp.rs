//! The MC4WP: Mailchimp for WordPress checker.
//! This module contains the checker used to determine if MC4WP: Mailchimp for WordPress is
//! used by the asset.
//! https://wordpress.org/plugins/mailchimp-for-wp/

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct Mc4wpChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Mc4wpChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: Stable tag: 5.2
        let source_code_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version1>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", (source_code_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running Mc4wpChecker::check_http_body() on {}",
            url_response.url
        );

        if url_response
            .url
            .contains("/wp-content/plugins/mailchimp-for-wp/readme.txt")
        {
            let body_regex_params = self
                .regexes
                .get("http-body-source")
                .expect("Regex Mc4wp/http-body-source not found");
            let (regex, keep_left, keep_right) = body_regex_params;
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Mc4wp/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left.to_owned(),
                keep_right.to_owned(),
                "Mc4wp",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }
        None
    }
}

impl<'a> Checker for Mc4wpChecker<'a> {}

impl<'a> HttpChecker for Mc4wpChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running Mc4wpChecker::check_http()");
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
        Technology::WPPMc4wp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = Mc4wpChecker::new();
        let body1 = r#"=== MC4WP: Mailchimp for WordPress ===
        Contributors: Ibericode, DvanKooten, hchouhan, lapzor
        Donate link: https://www.mc4wp.com/contribute/#utm_source=wp-plugin-repo&utm_medium=mailchimp-for-wp&utm_campaign=donate-link
        Tags: mailchimp, mc4wp, email, marketing, newsletter, subscribe, widget, mc4wp
        Requires at least: 4.6
        Tested up to: 6.3
        Stable tag: 4.9.10"#;
        let url1 = "https://www.example.com/blog/wp-content/plugins/mailchimp-for-wp/readme.txt";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 4.9.10",
            "Mc4wp",
            Some("4.9.10"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = Mc4wpChecker::new();
        let body = r#"Mc4wp can be found in stable tag: 5.1"#;
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
        let checker = Mc4wpChecker::new();
        let body1 = r#"=== MC4WP: Mailchimp for WordPress ===
        Contributors: Ibericode, DvanKooten, hchouhan, lapzor
        Donate link: https://www.mc4wp.com/contribute/#utm_source=wp-plugin-repo&utm_medium=mailchimp-for-wp&utm_campaign=donate-link
        Tags: mailchimp, mc4wp, email, marketing, newsletter, subscribe, widget, mc4wp,
        Requires at least: 4.6
        Tested up to: 6.3
        Stable tag: 3.8.12"#;
        let url1 = "https://www.example.com/wp-content/plugins/mailchimp-for-wp/readme.txt";
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
            "Stable tag: 3.8.12",
            "Mc4wp",
            Some("3.8.12"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = Mc4wpChecker::new();
        let body1 = r#"=== Another plugin ===
        Contributors: takayukister
        Donate link: https://anotherplugin.com/donate/
        Tags: contact, form, contact form, feedback, email, ajax, captcha, mailchimp-for-wp, multilingual
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
        let body2 = r#"How to install Mc4wp 2.2.4"#;
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
