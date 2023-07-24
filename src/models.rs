//! In this module are declared the entities manipulated by this program

use std::collections::HashMap;

use clap::{builder::PossibleValue, ValueEnum};
use regex::Regex;

/// Represents the type of scan
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScanType {
    /// Protocol TCP
    Tcp,
    /// Protocol UDP (not supported yet)
    Udp,
    /// Protocol HTTP
    Http,
}

impl ValueEnum for ScanType {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[ScanType::Tcp, ScanType::Http, ScanType::Udp]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            ScanType::Tcp => Some(PossibleValue::new("tcp")),
            ScanType::Http => Some(PossibleValue::new("http")),
            ScanType::Udp => Some(PossibleValue::new("udp")),
        }
    }
}

/// Represents a finding of a technology running on an asset
pub struct Finding {
    /// The technology found
    pub technology: String,
    /// The version of the technology
    /// Optional since it can be unknown
    pub version: Option<String>,
    /// The evidence of the finding
    pub evidence: String,
    /// The text for the evidence
    pub evidence_text: String,
    /// The URL where the finding has been found.
    pub url_of_finding: Option<String>,
}

impl Finding {
    /// Creates a new finding
    pub fn new(
        technology: &str,
        version: Option<&str>,
        evidence: &str,
        evidence_text: &str,
        url_of_finding: Option<&str>,
    ) -> Self {
        Finding {
            technology: technology.to_string(),
            version: version.map(|f| f.to_string()),
            evidence: evidence.to_string(),
            evidence_text: evidence_text.to_string(),
            url_of_finding: url_of_finding.map(|f| f.to_string()),
        }
    }
}

/// An enumeration to represent the technologies that Sanca can tried to identify.
/// In practice it is useful mainly for the web technologies to send only
/// HTTP requests needed to identify the given technologies.
/// As an example, it's not needed to send a request at /phpinfo.php
/// if we want to identify only the JavaScript libraries.
#[derive(Clone, PartialEq, Debug)]
pub enum Technology {
    Dovecot,
    Exim,
    MariaDB,
    MySQL,
    OpenSSH,
    ProFTPD,
    PureFTPd,
    /// OS is generic for all OSes.
    OS,
    PHP,
    PhpMyAdmin,
    Typo3,
    WordPress,
    Drupal,
    /// Apache httpd
    Httpd,
    Tomcat,
    Nginx,
    OpenSSL,
    JQuery,
    ReactJS,
    Handlebars,
    Lodash,
    AngularJS,
}

impl Technology {
    /// Returns the scan types matching the technology
    pub fn get_scans(&self) -> Vec<ScanType> {
        match self {
            Self::Dovecot | Self::Exim => vec![ScanType::Tcp],
            Self::MariaDB | Self::MySQL => vec![ScanType::Tcp],
            Self::OpenSSH | Self::ProFTPD | Self::PureFTPd => vec![ScanType::Tcp],
            Self::OS => vec![ScanType::Tcp, ScanType::Http],
            // Most technologies are about HTTP, so specify only the TCP, UDP
            // or multiple scan types, the rest will be HTTP-only
            _ => vec![ScanType::Http],
        }
    }

    /// Checks whether the technology supports the given scan type
    pub fn supports_scan(&self, scan_type: ScanType) -> bool {
        self.get_scans().contains(&scan_type)
    }

    /// Get the HTTP paths to request for a given technology
    pub fn get_url_requests(&self, main_url: &str) -> Vec<UrlRequest> {
        // Non-HTTP technologies don't need any paths
        if !self.supports_scan(ScanType::Http) {
            return Vec::new();
        }

        match self {
            Self::PHP => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "/phpinfo.php", false),
                    UrlRequest::from_path(main_url, "/info.php", false),
                    UrlRequest::from_path(main_url, "phpinfo.php", false),
                    UrlRequest::from_path(main_url, "info.php", false),
                    UrlRequest::from_path(main_url, "/pageNotFoundNotFound", false),
                ]
            }
            Self::Httpd | Self::Tomcat | Self::Nginx | Self::OpenSSL => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "/pageNotFoundNotFound", false),
                ]
            }
            _ => vec![UrlRequest::new(main_url, true)],
        }
    }
}

impl ValueEnum for Technology {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Technology::Dovecot,
            Technology::Exim,
            Technology::MariaDB,
            Technology::MySQL,
            Technology::OpenSSH,
            Technology::ProFTPD,
            Technology::PureFTPd,
            Technology::OS,
            Technology::PHP,
            Technology::PhpMyAdmin,
            Technology::WordPress,
            Technology::Drupal,
            Technology::Typo3,
            Technology::Httpd,
            Technology::Nginx,
            Technology::OpenSSL,
            Technology::JQuery,
            Technology::ReactJS,
            Technology::Handlebars,
            Technology::Lodash,
            Technology::AngularJS,
        ]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            Technology::Dovecot => Some(PossibleValue::new("dovecot")),
            Technology::Exim => Some(PossibleValue::new("exim")),
            Technology::MariaDB => Some(PossibleValue::new("mariadb")),
            Technology::MySQL => Some(PossibleValue::new("mysql")),
            Technology::OpenSSH => Some(PossibleValue::new("openssh")),
            Technology::ProFTPD => Some(PossibleValue::new("proftpd")),
            Technology::PureFTPd => Some(PossibleValue::new("pureftpd")),
            Technology::OS => Some(PossibleValue::new("os")),
            Technology::PHP => Some(PossibleValue::new("php")),
            Technology::PhpMyAdmin => Some(PossibleValue::new("phpmyadmin")),
            Technology::WordPress => Some(PossibleValue::new("wordpress")),
            Technology::Drupal => Some(PossibleValue::new("drupal")),
            Technology::Typo3 => Some(PossibleValue::new("typo3")),
            Technology::Httpd => Some(PossibleValue::new("httpd")),
            Technology::Tomcat => Some(PossibleValue::new("tomcat")),
            Technology::Nginx => Some(PossibleValue::new("nginx")),
            Technology::OpenSSL => Some(PossibleValue::new("openssl")),
            Technology::JQuery => Some(PossibleValue::new("jquery")),
            Technology::ReactJS => Some(PossibleValue::new("reactjs")),
            Technology::Handlebars => Some(PossibleValue::new("handlebars")),
            Technology::Lodash => Some(PossibleValue::new("lodash")),
            Technology::AngularJS => Some(PossibleValue::new("angularjs")),
        }
    }
}

/// Represents a request that an HTTP reader will have to handle
#[derive(Debug)]
pub struct UrlRequest {
    /// The URL where to send the HTTP request
    pub url: String,
    /// Whether to fetch the JavaScript files found in the response from url
    pub fetch_js: bool,
}

impl UrlRequest {
    /// Creates a list of UrlRequests based on a lits of technologies
    pub fn from_technologies(main_url: &str, technologies: &[Technology]) -> Vec<UrlRequest> {
        // Helps to avoid duplicated when building the list of UrlRequests
        // key is URL, value is fetch_js
        let mut url_requests_map: HashMap<String, bool> = HashMap::new();
        // For each technology, add its UrlRequests to the list, while avoiding
        // duplicates
        for technology in technologies {
            for url_request in technology.get_url_requests(main_url) {
                // If the URL is not stored already
                if !url_requests_map.contains_key(&url_request.url) {
                    url_requests_map.insert(url_request.url, url_request.fetch_js);
                } else if url_request.fetch_js == true {
                    // If the URL was already in the list but the new one has
                    // fetch_js to true, set fetch_js to true also in the list.
                    // It might be already set to true, but that's not important.
                    url_requests_map.insert(url_request.url, true);
                }
            }
        }

        // Convert the HashMap to a list of UrlRequest
        let mut url_requests: Vec<UrlRequest> = Vec::new();
        for (url, fetch_js) in url_requests_map.iter() {
            // The objective is to keep the main URL always in first position.
            // When possible, it's better to manage the main URL first, it will
            // be clearer for the user.
            if url == main_url {
                let mut tmp = vec![UrlRequest::new(url, *fetch_js)];
                tmp.extend(url_requests);
                url_requests = tmp;
            } else {
                url_requests.push(UrlRequest::new(url, *fetch_js));
            }
        }

        return url_requests;
    }

    /// Creates a new UrlRequest
    pub fn new(url: &str, fetch_js: bool) -> Self {
        UrlRequest {
            url: url.to_string(),
            fetch_js: fetch_js,
        }
    }

    /// Generate a new URL based on the original one and the path.
    ///
    /// # Example
    /// main_url = "https://example.com/blog/index.php"
    ///
    /// If path = "/phpinfo.php" the result will be https://example.com/phpinfo.php
    /// But if path = "phpinfo.php" the result will be https://example.com/blog/phpinfo.php
    pub fn from_path(main_url: &str, path_to: &str, fetch_js: bool) -> Self {
        // Note: this regex is not exhaustive. It doesn't support the
        // user:pass@hostname form, and it ignores the hash (#ancher1)
        // But it should enough for what we have to do with it.
        let url_regex = Regex::new(r"(?P<protocol>[a-z0-9]+):\/\/(?P<hostname>[^\/:]+)(:(?P<port>\d{1,5}))?(?P<path>\/[^\?]*)?(?P<querystring>\?[^#]*)?(#.*)?").unwrap();
        let caps = url_regex
            .captures(main_url)
            .expect(&format!("Unable to parse the provided URL: {}", main_url));
        let protocol: String = caps["protocol"].to_string();
        let hostname: String = caps["hostname"].to_string();
        // If the port is not provided, use the default for http / https
        let port: String = if caps.name("port").is_some() {
            caps.name("port").unwrap().as_str().to_string()
        } else {
            if protocol == "http" {
                "80".to_string()
            } else if protocol == "https" {
                "443".to_string()
            } else {
                panic!(
                    "Protocol {} not supported. Only http & https are supported",
                    protocol
                );
            }
        };
        // If no path is provided, uses /
        let path_from: String = if caps.name("path").is_some() {
            caps.name("path").unwrap().as_str().to_string()
        } else {
            "/".to_string()
        };
        let query_string: String = if caps.name("querystring").is_some() {
            caps.name("querystring").unwrap().as_str().to_string()
        } else {
            "".to_string()
        };

        let new_path: String = if path_to.starts_with("/") {
            // If an absolute path is provided, just use it
            path_to.to_string()
        } else {
            // Here handle the relative path in path_to
            let path_parts: Vec<String> = path_from.split("/").map(|i| i.to_string()).collect();

            if path_from.chars().nth(path_from.len() - 1).unwrap() == '/' {
                // If the last char of the original path is a /, concatenate the paths
                // Example: https://example.com/something/that/
                // In this case, a path of "test.php" would produce the URL
                // https://example.com/something/that/test.php
                format!("{}{}", path_from, path_to)
            } else if path_parts.len() <= 1 {
                // If we were at the top of the tree, just use path_to
                // Example: https://example.com/something
                // In this case, a path_to of "other/index.php" would produce the URL
                // https://example.com/other/index.php
                path_to.to_string()
            } else {
                // If we have an original path with several parts and not ending with a /,
                // just remove the last part.
                // Example: https://example.com/this/that.php
                // In this case, a path of "index.php" would produce the URL
                // https://example.com/this/index.php
                let mut np = "".to_string();
                let mut part_counter = 0;

                for part in path_parts.iter() {
                    // We take all parts except the last one
                    if part_counter < path_parts.len() - 1 && !part.is_empty() {
                        np.push_str(&format!("/{}", part));
                    }
                    part_counter += 1;
                }

                np.push_str(&format!("/{}", path_to));
                np
            }
        };

        // Avoid sending requests with a '?' if no query string is provided
        let qs = if query_string.is_empty() {
            "".to_string()
        } else {
            format!("?{}", query_string)
        };
        let url = format!("{}://{}:{}{}{}", protocol, hostname, port, new_path, qs);
        Self::new(&url, fetch_js)
    }
}

/// Represents the response returned by an HTTP reader
pub struct UrlResponse {
    /// The URL where the request was sent
    pub url: String,
    /// The response headers
    pub headers: HashMap<String, String>,
    /// The response body
    pub body: String,
}

impl UrlResponse {
    /// Creates a new UrlResponse
    pub fn new(url: &str, headers: HashMap<String, String>, body: &str) -> Self {
        UrlResponse {
            url: url.to_string(),
            headers,
            body: body.to_string(),
        }
    }

    /// Return a HashMap with only the headers given in parameter.
    /// Any non-existing header is ignored.
    pub fn get_headers(&self, header_names: &[String]) -> HashMap<String, String> {
        let mut headers: HashMap<String, String> = HashMap::new();
        for header_name in header_names {
            let header_option = self.headers.get(header_name);
            if header_option.is_some() {
                headers.insert(header_name.to_owned(), header_option.unwrap().to_owned());
            }
        }
        headers
    }
}

impl PartialEq for UrlResponse {
    /// Two UrlResponse are considered equal if their URLs
    /// are identical. It is to avoid duplicate.
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}
