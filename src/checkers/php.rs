//! The PHP checker.
//! This module contains the checker used to determine if PHP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
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
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
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
                return vec![header_finding.unwrap()];
            }

            let body_finding = self.check_http_body(url_response);
            if body_finding.is_some() {
                return vec![body_finding.unwrap()];
            }
        }
        return Vec::new();
    }

    /// The technology supported by the checker.
    fn get_technology(&self) -> Technology {
        Technology::PHP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = PHPChecker::new();
        let body1 = r#"<h1 class="p">PHP Version 8.2.0</h1>"#;
        let url1 = "https://www.example.com/phpinfo.php";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "PHP Version 8.2.0",
            "PHP",
            Some("8.2.0"),
            Some(url1),
        );

        let body2 = r#"<h1 class="p">PHP Version 8.2.1-alpha</h1>"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "PHP Version 8.2.1",
            "PHP",
            Some("8.2.1-alpha"),
            Some(url1),
        );
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
        let url1 = "https://www.example.com/that.php?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, headers1, "the body", UrlRequestType::Default);
        let finding = checker.check_http_headers(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "PHP/8.2.1",
            "PHP",
            Some("8.2.1"),
            Some(url1),
        );

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        headers2.insert("Server".to_string(), "nginx/1.22.0 (CentOS)".to_string());
        headers2.insert("X-powered-by".to_string(), "PHP/7.4".to_string());
        url_response_valid.headers = headers2;
        let finding = checker.check_http_headers(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(&finding.unwrap(), "PHP/7.4", "PHP", Some("7.4"), Some(url1));
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
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_headers(&url_response_invalid);
        assert!(finding.is_none());

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        url_response_invalid.headers = headers2;
        url_response_invalid.request_type = UrlRequestType::Default;
        let finding = checker.check_http_headers(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = PHPChecker::new();
        let body1 = r#"<h1 class="p">PHP Version 5.6.40</h1>"#;
        let url1 = "https://www.example.com/info.php";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "PHP Version 5.6.40",
            "PHP",
            Some("5.6.40"),
            Some(url1),
        );

        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert(
            "Server".to_string(),
            "nginx/1.22.2 OpenSSL/1.0.2k PHP/8.1".to_string(),
        );
        let url2 = "https://www.example.com/test.php";
        let url_response_valid =
            UrlResponse::new(url2, headers1, "the body", UrlRequestType::Default);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let findings = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert_eq!(1, findings.len());
        check_finding_fields(&findings[0], "PHP/8.1", "PHP", Some("8.1"), Some(url2));
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
        headers1.insert("Server".to_string(), "Apache/2.4.52 PHP/7.1".to_string());
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            headers1,
            "the body",
            UrlRequestType::JavaScript,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(
            findings.is_empty(),
            "PHP must not be detected on JavaScript URLs to avoid false positive"
        );
    }
}
