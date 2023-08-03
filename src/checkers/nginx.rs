//! The Nginx checker.
//! This module contains the checker used to determine if Nginx is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The Nginx checker
pub struct NginxChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> NginxChecker<'a> {
    /// Creates a new NginxChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: nginx/1.22.3 (Debian)
        let header_regex =
            Regex::new(r"^(?P<wholematch>nginx(\/(?P<version>\d+(\.\d+(\.\d+)?)?))?)").unwrap();
        // Example: <hr><center>nginx/1.22.3</center>
        let body_regex = Regex::new(r"<hr><center>(?P<wholematch>nginx(\/(?P<version>\d+\.\d+\.\d+)( \([^\)]+\)))?)</center>").unwrap();

        regexes.insert("http-header", header_regex);
        regexes.insert("http-body", body_regex);
        Self { regexes: regexes }
    }

    /// Check for the technology in HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running NginxChecker::check_http_headers() on {}",
            url_response.url
        );
        // Check the HTTP headers of each UrlResponse
        let headers_to_check =
            url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

        // Check in the headers to check present in this UrlResponse
        for (header_name, header_value) in headers_to_check {
            trace!("Checking header: {} / {}", header_name, header_value);
            let caps_result = self
                .regexes
                .get("http-header")
                .expect("Regex \"http-header\" not found.")
                .captures(&header_value);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Nginx/http-header matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 45, 45, "Nginx", &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)));
            }
        }
        None
    }

    /// Check for the technology in the body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!("Running check_http_body() on {}", url_response.url);
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Nginx/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 15, "Nginx", "$techno_name$$techno_version$ has been identified by looking at its signature \"$evidence$\" at this page: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for NginxChecker<'a> {
    /// Check if the asset is running Nginx.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running NginxChecker::check_http()");
        for url_response in data {
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
        Technology::Nginx
    }
}
