//! The Really Simple SSL checker.
//! This module contains the checker used to determine if Really Simple SSL is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::HttpChecker;
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct ReallySimpleSSLChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ReallySimpleSSLChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: Stable tag: 5.2
        let source_code_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ReallySimpleSSLChecker::check_http_body() on {}",
            url_response.url
        );

        if url_response
            .url
            .contains("/wp-content/plugins/really-simple-ssl/readme.txt")
        {
            let caps_result = self
                .regexes
                .get("http-body-source")
                .expect("Regex \"http-body-source\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex ReallySimpleSSL/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "ReallySimpleSSL",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }
        None
    }
}

impl<'a> HttpChecker for ReallySimpleSSLChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running ReallySimpleSSLChecker::check_http()");
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
        Technology::WPPReallySimpleSSL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = ReallySimpleSSLChecker::new();
        let body1 = r#"=== Really Simple SSL ===
        Contributors: RogierLankhorst, markwolters, hesseldejong, vicocotea, marcelsanting, janwoostendorp
        Donate link: https://www.paypal.me/reallysimplessl
        Tags: SSL, https, force SSL, mixed content, security, secure website, website security, TLS, secure socket layers, HSTS
        Requires at least: 5.8
        License: GPL2
        Tested up to: 6.4
        Requires PHP: 7.2
        Stable tag: 7.2.0"#;
        let url1 = "https://www.example.com/blog/wp-content/plugins/really-simple-ssl/readme.txt";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 7.2.0",
            "ReallySimpleSSL",
            Some("7.2.0"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = ReallySimpleSSLChecker::new();
        let body = r#"ReallySimpleSSL can be found in stable tag: 5.1"#;
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
        let checker = ReallySimpleSSLChecker::new();
        let body1 = r#"=== Really Simple SSL ===
        Contributors: RogierLankhorst, markwolters, hesseldejong, vicocotea, marcelsanting, janwoostendorp
        Donate link: https://www.paypal.me/reallysimplessl
        Tags: SSL, https, force SSL, mixed content, security, secure website, website security, TLS, secure socket layers, HSTS
        Requires at least: 5.8
        License: GPL2
        Tested up to: 6.4
        Requires PHP: 7.2
        Stable tag: 7.1.2"#;
        let url1 = "https://www.example.com/wp-content/plugins/really-simple-ssl/readme.txt";
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
            "Stable tag: 7.1.2",
            "ReallySimpleSSL",
            Some("7.1.2"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = ReallySimpleSSLChecker::new();
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
        let body2 = r#"How to install ReallySimpleSSL 2.2.4"#;
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
