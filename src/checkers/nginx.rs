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
        let header_regex = Regex::new(r"^nginx(\/(?P<nginxversion>\d+\.\d+(\.\d+)?))?").unwrap();
        regexes.insert("http-header", header_regex);
        NginxChecker { regexes: regexes }
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
            // Check the HTTP headers of each UrlResponse
            let headers = &url_response.headers;
            let mut headers_to_check = HashMap::new();

            let server_header = headers.get("server");
            if server_header.is_some() {
                headers_to_check.insert("Server", server_header.unwrap());
            }

            let x_powered_by_header = headers.get("x-powered-by");
            if x_powered_by_header.is_some() {
                headers_to_check.insert("X-Powered-By", x_powered_by_header.unwrap());
            }

            // Check in the headers to check that were present in this UrlResponse
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
                    if nginx_version_match.is_some() {
                        nginx_version = Some(nginx_version_match.unwrap().as_str());
                    }
                    let mut nginx_version_text = String::new();
                    if nginx_version.is_some() {
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
        }
        return None;
    }

    /// This checker supports Apache httpd
    fn get_technology(&self) -> Technology {
        Technology::Httpd
    }
}
