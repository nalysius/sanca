//! The OpenSSL checker.
//! This module contains the checker used to determine if OpenSSL is
//! used by the asset and in which version.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The OpenSSL checker
pub struct OpenSSLChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> OpenSSLChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: OpenSSL/1.0.2k-fips
        let header_regex = Regex::new(
            r"(?P<wholematch>.*OpenSSL\/(?P<version>\d+\.\d+\.\d+([a-z])?(-[a-z]+)?).*)",
        )
        .unwrap();
        regexes.insert("http-header", header_regex);
        Self { regexes: regexes }
    }

    /// Checks in the HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running OpenSSLChecker::check_http_headers() on {}",
            url_response.url
        );
        // Check the HTTP headers of each UrlResponse
        let headers_to_check =
            url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

        // Check in the headers to check that were present in this UrlResponse
        for (header_name, header_value) in headers_to_check {
            trace!("Checking header: {} / {}", header_name, header_value);
            let caps_result = self
                .regexes
                .get("http-header")
                .expect("Regex \"http-header\" not found.")
                .captures(&header_value);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex OpenSSH/http-header matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 45, 45, "OpenSSL", &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)));
            }
        }
        None
    }
}

impl<'a> HttpChecker for OpenSSLChecker<'a> {
    /// Check if the asset is running OpenSSL.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let response = self.check_http_headers(url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// This checker supports Apache httpd
    fn get_technology(&self) -> Technology {
        Technology::OpenSSL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;

    #[test]
    fn header_matches() {
        let checker = OpenSSLChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "Apache/2.4.50 OpenSSL/1.0.2k".to_string(),
        );
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/that.php?abc=def",
            headers1,
            "the body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http_headers(&url_response_valid);
        assert!(finding.is_some());

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        headers2.insert(
            "X-powered-by".to_string(),
            "nginx/1.22.0 (CentOS) OpenSSL/1.0.2k-fips".to_string(),
        );
        url_response_valid.headers = headers2;
        let finding = checker.check_http_headers(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn header_doesnt_matches() {
        let checker = OpenSSLChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "Apache/2.4.51 (Debian) OpenSSL 1.0.2k".to_string(),
        );
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.php?abc=def",
            headers1,
            "the body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http_headers(&url_response_invalid);
        assert!(finding.is_none());

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        url_response_invalid.headers = headers2;
        let finding = checker.check_http_headers(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = OpenSSLChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "Apache/2.4.51 (Debian) OpenSSL/1.0.2k".to_string(),
        );

        let url_response_valid = UrlResponse::new(
            "https://www.example.com/pageNotFound.html",
            headers1,
            "the body",
            UrlRequestType::Default,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert!(finding.is_some());

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        headers2.insert(
            "Server".to_string(),
            "nginx/1.22.2 OpenSSL/1.0.2k-fips".to_string(),
        );
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/test.php",
            headers2,
            "the body",
            UrlRequestType::Default,
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
        let checker = OpenSSLChecker::new();
        let body1 = r#"About OpenSSL 1.0.2k"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );

        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            headers1,
            "the body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_fields_are_valid() {
        let checker = OpenSSLChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "Apache/2.4.51 (Debian) OpenSSL/1.0.2k".to_string(),
        );

        let url = "https://www.example.com/404.php";
        let url_response_valid1 =
            UrlResponse::new(url, headers1, "the body", UrlRequestType::Default);
        let finding = checker.check_http_headers(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "OpenSSL/1.0.2k";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("OpenSSL", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("1.0.2k", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("OpenSSL 1.0.2k")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
