//! In this module are defined the structs and methods related to
//! HTTP requests and responses.

use super::technology::Technology;
use log::{error, trace};
use regex::Regex;
use std::collections::HashMap;

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
        trace!("Running UrlRequest::from_technologies()");
        // Helps to avoid duplicated when building the list of UrlRequests
        // key is URL, value is fetch_js
        let mut url_requests_map: HashMap<String, bool> = HashMap::new();
        trace!("Looping over provided technologies");
        // For each technology, add its UrlRequests to the list, while avoiding
        // duplicates
        for technology in technologies {
            trace!("Checking {:?}", technology);
            for url_request in technology.get_url_requests(main_url) {
                trace!("Handling UrlRequest {:?}", url_request);
                // If the URL is not stored already
                if !url_requests_map.contains_key(&url_request.url) {
                    trace!("UrlRequest is not already in the list, add it");
                    url_requests_map.insert(url_request.url, url_request.fetch_js);
                } else if url_request.fetch_js == true {
                    trace!("UrlRequest already in the list, but this time fetch_js is true, update the already stored value");
                    // If the URL was already in the list but the new one has
                    // fetch_js to true, set fetch_js to true also in the list.
                    // It might be already set to true, but that's not important.
                    url_requests_map.insert(url_request.url, true);
                }
            }
        }

        trace!("Converting the HashMap of UrlRequests to a Vec");
        // Convert the HashMap to a list of UrlRequest
        let mut url_requests: Vec<UrlRequest> = Vec::new();
        for (url, fetch_js) in url_requests_map.iter() {
            // The objective is to keep the main URL always in first position.
            // When possible, it's better to manage the main URL first, it will
            // be clearer for the user.
            if url == main_url {
                trace!("The URL is the main, add it in the first position");
                let mut tmp = vec![UrlRequest::new(url, *fetch_js)];
                tmp.extend(url_requests);
                url_requests = tmp;
            } else {
                trace!("Pushing UrlRequest {} / {} to the list", url, fetch_js);
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
        trace!("Running UrlRequest::from_path()");
        // Note: this regex is not exhaustive. It doesn't support the
        // user:pass@hostname form, and it ignores the hash (#ancher1)
        // But it should enough for what we have to do with it.
        let url_regex = Regex::new(r"(?P<protocol>[a-z0-9]+):\/\/(?P<hostname>[^\/:]+)(:(?P<port>\d{1,5}))?(?P<path>\/[^\?]*)?(?P<querystring>\?[^#]*)?(#.*)?").unwrap();
        let caps = url_regex
            .captures(main_url)
            .expect(&format!("Unable to parse the provided URL: {}", main_url));
        let protocol: String = caps["protocol"].to_string();
        let hostname: String = caps["hostname"].to_string();
        trace!(
            "Handling main_url. Protocol = {}, hostname = {}",
            protocol,
            hostname
        );
        // If the port is not provided, use the default for http / https
        let port: String = if caps.name("port").is_some() {
            trace!("Port = {}", caps.name("port").unwrap().as_str());
            format!(":{}", caps.name("port").unwrap().as_str().to_string())
        } else {
            trace!("Port not provided. 80 is default for HTTP & 443 default for HTTPS");
            "".to_string()
        };
        // If no path is provided, uses /
        let path_from: String = if caps.name("path").is_some() {
            trace!(
                "Found a path in the main URL: {}",
                caps.name("path").unwrap().as_str()
            );
            caps.name("path").unwrap().as_str().to_string()
        } else {
            trace!("No path found in the main URL, use /");
            "/".to_string()
        };

        let new_path: String = if path_to.starts_with("/") {
            // If an absolute path is provided, just use it
            path_to.to_string()
        } else {
            trace!("The path found in the main URL is relative, compute the new path");
            // Here handle the relative path in path_to
            let path_parts: Vec<String> = path_from.split("/").map(|i| i.to_string()).collect();

            if path_from.chars().nth(path_from.len() - 1).unwrap() == '/' {
                trace!("The last char of the main URL path is a /");
                // If the last char of the original path is a /, concatenate the paths
                // Example: https://example.com/something/that/
                // In this case, a path of "test.php" would produce the URL
                // https://example.com/something/that/test.php
                format!("{}{}", path_from, path_to)
            } else if path_parts.len() <= 1 {
                trace!("The main URL path has only one part (/something), just use the new one");
                // If we were at the top of the tree, just use path_to
                // Example: https://example.com/something
                // In this case, a path_to of "other/index.php" would produce the URL
                // https://example.com/other/index.php
                path_to.to_string()
            } else {
                trace!(
                    "The main URL path has several parts and doesn't end with a / (/some/thing)"
                );
                // If we have an original path with several parts and not ending with a /,
                // just remove the last part.
                // Example: https://example.com/this/that.php
                // In this case, a path of "index.php" would produce the URL
                // https://example.com/this/index.php
                let mut np = "".to_string();
                let mut part_counter = 0;

                trace!("Loop over each path part to remove the last one");
                for part in path_parts.iter() {
                    trace!("Checking path part {}", part);
                    // We take all parts except the last one
                    if part_counter < path_parts.len() - 1 && !part.is_empty() {
                        trace!("Part is not the last one, use it");
                        np.push_str(&format!("/{}", part));
                    }
                    part_counter += 1;
                }

                trace!("The last part of the original path has been removed, add the new one");
                np.push_str(&format!("/{}", path_to));
                np
            }
        };

        let url = format!("{}://{}{}{}", protocol, hostname, port, new_path);
        Self::new(&url, fetch_js)
    }

    /// Get the IP or hostname & the port of the URL
    pub fn get_hostname_port(&self) -> (String, u16) {
        // Note: this regex is not exhaustive. It doesn't support the
        // user:pass@hostname form, and it ignores the hash (#ancher1)
        // But it should enough for what we have to do with it.
        let url_regex =
            Regex::new(r"(?P<protocol>[a-z0-9]+):\/\/(?P<hostname>[^\/:]+)(:(?P<port>\d{1,5}))?")
                .unwrap();
        let caps = url_regex
            .captures(&self.url)
            .expect(&format!("Unable to parse the provided URL: {}", self.url));
        let protocol: String = caps["protocol"].to_string();
        let hostname: String = caps["hostname"].to_string();
        let port = if caps.name("port").is_some() {
            caps["port"].to_string()
        } else {
            if protocol == "https" {
                "443".to_string()
            } else if protocol == "http" {
                "80".to_string()
            } else {
                error!("Unknown protocol: {}", protocol);
                panic!("Unknown protocol: {}", protocol);
            }
        };
        (hostname, str::parse::<u16>(&port).unwrap())
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
    /// The request type.
    /// Was it a "main" request, of a subsequent one to download
    /// a JavaScript file?
    pub request_type: UrlRequestType,
}

impl UrlResponse {
    /// Creates a new UrlResponse
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        body: &str,
        request_type: UrlRequestType,
    ) -> Self {
        UrlResponse {
            url: url.to_string(),
            headers,
            body: body.to_string(),
            request_type,
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

/// Represents the type of a UrlRequest.
/// It is about a main URL, or a JavaScript one.
#[derive(PartialEq)]
pub enum UrlRequestType {
    /// The default UrlRequest type.
    /// Used for "main" requests, not for subsequent
    /// requests like fetching JavaScript.
    Default,
    /// The UrlRequest is the one of a JavaScript file.
    JavaScript,
}
