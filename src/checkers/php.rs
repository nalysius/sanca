//! The PHP checker.
//! This module contains the checker used to determine if PHP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The PHP checker
pub struct PHPChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PHPChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: PHP/7.1.33.12
        let header_regex =
            Regex::new(r"(?P<wholematch>.*PHP\/(?P<version>\d+\.\d+(\.\d+(\.\d+)?)?).*)").unwrap();
        // Example: <h1 class="p">PHP Version 8.2.2</h1>
        let body_regex = Regex::new(r#"(?P<wholematch><h1 class="p">PHP Version (?P<version>\d+\.\d+\.\d+(-[a-z0-9._-]+)?)</h1>)"#).unwrap();

        regexes.insert("http-header", header_regex);
        regexes.insert("http-body", body_regex);
        Self { regexes: regexes }
    }

    /// Check in the HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PHPChecker::check_http_headers() on {}",
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
                info!("Regex PHP/http-header matches");
                let caps = caps_result.unwrap();
                return Some(
                    self.extract_finding_from_captures(
                        caps,
                        url_response,
                        45,
                        45,
                        "PHP",
                        &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)
                    )
                );
            }
        }
        None
    }

    /// Check for the technology in the body
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PHPChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex PHP/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "PHP", "$techno_name$$techno_version$ has been identified by looking at the phpinfo()'s output \"$evidence$\" at this page: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for PHPChecker<'a> {
    /// Check if the asset is running PHP.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running PHPChecker::check_http()");
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let header_finding = self.check_http_headers(url_response);
            if header_finding.is_some() {
                return header_finding;
            }

            let body_finding = self.check_http_body(url_response);
            if body_finding.is_some() {
                return body_finding;
            }
        }
        return None;
    }

    /// The technology supported by the checker.
    fn get_technology(&self) -> Technology {
        Technology::PHP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = PHPChecker::new();
        let body1 = r#"<h1 class="p">PHP Version 8.2.0</h1>"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/phpinfo.php",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = r#"<h1 class="p">PHP Version 8.2.1-alpha</h1>"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = PHPChecker::new();
        let body = r#"<h1>PHP 8.2</h1>"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/about.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn header_matches() {
        let checker = PHPChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "Apache/2.4.52 PHP/8.2.1".to_string());
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
        headers2.insert("Server".to_string(), "nginx/1.22.0 (CentOS)".to_string());
        headers2.insert("X-powered-by".to_string(), "PHP/7.4".to_string());
        url_response_valid.headers = headers2;
        let finding = checker.check_http_headers(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn header_doesnt_match() {
        let checker = PHPChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "Apache/2.4.51".to_string());
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
        let checker = PHPChecker::new();
        let body1 = r#"<h1 class="p">PHP Version 5.6.40</h1>"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/info.php",
            HashMap::new(),
            body1,
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

        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "nginx/1.22.2 OpenSSL/1.0.2k PHP/8.1".to_string(),
        );
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/test.php",
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
        let finding = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert!(finding.is_some());
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = PHPChecker::new();
        let body1 = r#"About PHP 8.2.11"#;
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
        let checker = PHPChecker::new();
        let body1 = r#"<h1 class="p">PHP Version 8.2.0</h1>"#;
        let url = "https://www.example.com/404.php";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::Default);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "PHP Version 8.2.0";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("PHP", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("8.2.0", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("PHP 8.2.0")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
