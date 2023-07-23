//! The Nginx checker.
//! This module contains the checker used to determine if Nginx is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::{Match, Regex};

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
        let header_regex = Regex::new(r"^nginx(\/(?P<nginxversion>\d+(\.\d+(\.\d+)?)?))?").unwrap();
        // Example: <address>Apache/2.4.52 (Debian) Server at localhost Port 80</address>
        let body_regex = Regex::new(r"<hr><center>(?P<wholematch>nginx(\/(?P<version>\d+\.\d+\.\d+)( \([^\)]+\)))?)</center>").unwrap();

        regexes.insert("http-header", header_regex);
        regexes.insert("http-body", body_regex);
        Self { regexes: regexes }
    }

    /// Check for the technology in HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        // Check the HTTP headers of each UrlResponse
        let headers_to_check =
            url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

        // Check in the headers to check present in this UrlResponse
        for (header_name, header_value) in headers_to_check {
            let caps_result = self
                .regexes
                .get("http-header")
                .expect("Regex \"http-header\" not found.")
                .captures(&header_value);

            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let evidence = &format!("{}: {}", header_name, header_value);
                let nginx_version_match: Option<Match> = caps.name("nginxversion");
                let mut nginx_version: Option<&str> = None;
                let mut nginx_version_text = String::new();
                if nginx_version_match.is_some() {
                    nginx_version = Some(nginx_version_match.unwrap().as_str());
                    // Add a space in the version, so in the evidence text we
                    // avoid a double space if the version is not found
                    nginx_version_text = format!(" {}", nginx_version.unwrap());
                }

                let evidence_text = format!(
                "Nginx{} has been identified using the HTTP header \"{}\" returned at the following URL: {}",
                nginx_version_text,
                evidence,
                url_response.url
            );

                return Some(Finding::new(
                    "Nginx",
                    nginx_version,
                    &evidence,
                    &evidence_text,
                    Some(&url_response.url),
                ));
            }
        }
        None
    }

    /// Check for the technology in the body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            let evidence = caps["wholematch"].to_string();
            let version_match: Option<Match> = caps.name("version");
            let mut version: Option<&str> = None;
            let mut version_text = String::new();
            if version_match.is_some() {
                version = Some(version_match.unwrap().as_str());
                // Add a space in the version, so in the evidence text we
                // avoid a double space if the version is not found
                version_text = format!(" {}", version.unwrap());
            }

            let evidence_text = format!(
                "Nginx{} has been identified by looking at its signature \"{}\" at this page: {}",
                version_text, evidence, url_response.url
            );

            return Some(Finding::new(
                "Nginx",
                version,
                &evidence,
                &evidence_text,
                Some(&url_response.url),
            ));
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
