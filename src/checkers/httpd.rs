//! The Apache httpd checker.
//! This module contains the checker used to determine if Apache httpd is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The Apache httpd checker
pub struct ApacheHttpdChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ApacheHttpdChecker<'a> {
    /// Creates a new ApacheHttpdChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: Apache/2.4.52 (Debian)
        let header_regex =
            Regex::new(r"^(?P<wholematch>.*Apache(\/(?P<version>\d+(\.\d+(\.\d+)?)?))?.*)")
                .unwrap();
        // Example: <address>Apache/2.4.52 (Debian) Server at localhost Port 80</address>
        let body_regex = Regex::new(r"<address>(?P<wholematch>Apache((\/(?P<version>\d+\.\d+\.\d+)( \([^\)]+\)))? Server at (<a href=.[a-zA-Z0-9.@:+_-]*.>)?[a-zA-Z0-9-.]+(</a>)? Port \d+)?)</address>").unwrap();

        regexes.insert("http-header", header_regex);
        regexes.insert("http-body", body_regex);
        Self { regexes: regexes }
    }

    /// Check for the technology in HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ApacheHttpdChecker::check_http_headers() on {}",
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
                info!("Regex ApacheHttpd/http-header matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 45, 45, "Apache httpd", &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)));
            }
        }
        None
    }

    /// Check for the technology in the body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ApacheHttpdChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex ApacheHttpd/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 45, 45, "Apache httpd", "$techno_name$$techno_version$ has been identified by looking at its signature \"$evidence$\" at this page: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for ApacheHttpdChecker<'a> {
    /// Check if the asset is running Apache httpd.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running ApacheHttpdChecker::check_http()");
        for url_response in data {
            trace!("Checking {}", url_response.url);
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            // Check in HTTP headers first
            let header_finding = self.check_http_headers(url_response);
            if header_finding.is_some() {
                return header_finding;
            }
            // Check in response body then
            let body_finding = self.check_http_body(url_response);
            if body_finding.is_some() {
                return body_finding;
            }
        }
        None
    }

    /// This checker supports Apache httpd
    fn get_technology(&self) -> Technology {
        Technology::Httpd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = ApacheHttpdChecker::new();
        let body1 = r#"<p><address>Apache Server at www.test-domain.com Port 80</address></p>"#;
        let url1 = "https://www.example.com/pageNotFound";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default);
        let finding = checker.check_http_body(&url_response_valid);
        check_finding_fields(finding, "Apache Server", "Apache httpd", None, Some(url1));

        let body2 = r#"<p><address>Apache/2.4.52 (Debian) Server at <a href="mailto:webmaster@test-domain.com">www.test-domain.com</a> Port 80</address></p>"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        check_finding_fields(
            finding,
            "Apache/2.4.52",
            "Apache httpd",
            Some("2.4.52"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = ApacheHttpdChecker::new();
        let body = r#"<address>Apache 2.4.52 server</address>"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/not-found.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn header_matches() {
        let checker = ApacheHttpdChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "Apache/2.4.52".to_string());
        let url1 = "https://www.example.com/that.php?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, headers1, "the body", UrlRequestType::Default);
        let finding = checker.check_http_headers(&url_response_valid);
        check_finding_fields(
            finding,
            "Apache/2.4.52",
            "Apache httpd",
            Some("2.4.52"),
            Some(url1),
        );

        let mut headers2 = HashMap::new();
        headers2.insert("Accept".to_string(), "text/html".to_string());
        headers2.insert("Server".to_string(), "Apache/2.4.52 (CentOS)".to_string());
        url_response_valid.headers = headers2;
        let finding = checker.check_http_headers(&url_response_valid);
        check_finding_fields(
            finding,
            "Apache/2.4.52",
            "Apache httpd",
            Some("2.4.52"),
            Some(url1),
        );
    }

    #[test]
    fn header_doesnt_match() {
        let checker = ApacheHttpdChecker::new();
        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "nginx/1.22.0".to_string());
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
        url_response_invalid.request_type = UrlRequestType::JavaScript;
        let finding = checker.check_http_headers(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = ApacheHttpdChecker::new();
        let body1 = r#"<address>Apache Server at www.test-domain.com Port 80</address>"#;
        let url1 = "https://www.example.com/pageNotFound.html";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        check_finding_fields(finding, "Apache Server", "Apache httpd", None, Some(url1));

        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "Apache/2.4.52".to_string());
        let url2 = "https://www.example.com/test.php";
        let url_response_valid =
            UrlResponse::new(url2, headers1, "the body", UrlRequestType::Default);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_valid, url_response_invalid]);
        check_finding_fields(
            finding,
            "Apache/2.4.52",
            "Apache httpd",
            Some("2.4.52"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = ApacheHttpdChecker::new();
        let body1 = r#"About Apache httpd 2.4.54"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );

        let mut headers1 = HashMap::new();
        headers1.insert("Accept".to_string(), "text/html".to_string());
        headers1.insert("Server".to_string(), "Apache/2.4.41".to_string());
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            headers1,
            "the body",
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(
            finding.is_none(),
            "Apache httpd must not be detected on JavaScript URLs to avoid false positive"
        );
    }
}
