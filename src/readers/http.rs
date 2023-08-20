//! Fetch data over HTTP(S)
//!
//! The [`HttpReader`] is there to fetch resources via HTTP(S), to identify the
//! technologies being used by the remote host.

use std::collections::HashMap;

use futures::future::join_all;
use log::{debug, error, trace};
use regex::Regex;
use reqwest::Client;

use crate::models::reqres::{UrlRequest, UrlRequestType, UrlResponse};

/// A reader used to fetch HTTP(S) resources.
///
/// It's able to send several requests according to the technologies being
/// wanted. If a JavaScript library is wanted, the reader extracts the
/// JavaScript URLs from the main HTTP response and fetch them too.
///
/// The `HttpReader` works asynchronously, to fetch all data in a minimum amount
/// of time.
pub struct HttpReader {
    /// The regex to find URLs
    url_regex: Regex,
}

impl HttpReader {
    /// Creates a new HttpReader
    pub fn new() -> Self {
        let url_regex = Regex::new(
            r#"<script[^>]+src\s*=\s*["']?\s*(?P<url>(((?P<protocol>[a-z0-9]+):)?\/\/(?P<hostname>[^\/:]+)(:(?P<port>\d{1,5}))?)?(?P<path>\/?[a-zA-Z0-9\/._ %@-]*(?P<extension>\.[a-zA-Z0-9_-]+)?)?(?P<querystring>\?[^#\s">]*)?(#[^">\s]*)?)\s*["']?"#
        ).unwrap();
        HttpReader { url_regex }
    }

    /// Reads via HTTP(S)
    /// Sends HTTP requests to each URL to fetch the response, and
    /// optionally requests the JavaScript files found in the response body.
    pub async fn read(&self, url_requests: &[UrlRequest]) -> Vec<UrlResponse> {
        trace!("Running HttpReader::read()");
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Unable to create an HTTP client.");

        // Here we store all the Futures of the http requests
        // They will be handled all together in parallel
        let mut url_responses_futures = Vec::new();

        for url_request in url_requests {
            trace!(
                "Pushing {} / fetch_js = {} to the list of UrlRequests to fetch",
                url_request.url,
                url_request.fetch_js
            );
            url_responses_futures.push(self.read_one_page(url_request, &http_client));
        }

        trace!("Waiting for all the UrlRequests to be handled");
        // Send all the HTTP requests, and wait for the result
        let responses_results = join_all(url_responses_futures).await;
        trace!("All UrlRequests handled");
        let mut responses_clean: Vec<UrlResponse> = Vec::new();
        // Add each successfull response to the list
        // responses_results is a Vec<Result<Vec<UrlResponse>, String>>
        // so we have to unpack each Result and concatenate all the
        // Vec<UrlResponse>
        for response_result in responses_results {
            if response_result.is_ok() {
                let mut response = response_result.unwrap();
                responses_clean.append(&mut response);
            }
        }
        responses_clean
    }

    /// Reads one page via HTTP(S)
    /// Sends an HTTP request to the url to fetch the response, and
    /// optionally requests the JavaScript files found in the response
    async fn read_one_page(
        &self,
        url_request: &UrlRequest,
        http_client: &Client,
    ) -> Result<Vec<UrlResponse>, String> {
        trace!("Running HttpChecker::read_one_page()");
        debug!("Sending HTTP request for URL {}", url_request.url);
        let mut responses: Vec<UrlResponse> = Vec::new();
        let main_response_result = self
            .http_request(&url_request, http_client, UrlRequestType::Default)
            .await;
        if let Err(e) = main_response_result {
            error!("An error occured while reading one page: {:?}", e);
            return Err(e);
        }

        trace!("Pushing the HTTP response to the list");
        let main_response = main_response_result.unwrap();
        let main_response_body = main_response.body.clone();
        responses.push(main_response);

        if url_request.fetch_js {
            debug!("Fetch JS is true for URL {}", url_request.url);
            let url_requests_js =
                // Don't provide extension here, some scripts don't use the .js
                self.extract_urls(&url_request.url, &main_response_body, None);
            trace!(
                "The following URLs have been found in the response body: {:?}",
                url_requests_js
            );

            // Here we store all the Futures of the http requests
            // They will be handled all together in parallel
            let url_responses_futures = url_requests_js.iter().map(|i| {
                let response_future =
                    self.http_request(&i, &http_client, UrlRequestType::JavaScript);
                response_future
            });

            trace!("Waiting for all the subsequent HTTP requests to be handled");
            // Send all the HTTP requests, and wait for the result
            let responses_results = join_all(url_responses_futures).await;
            trace!("Subsequent HTTP requests handled");
            // Add each successfull response to the list
            // responses_results is a Vec<Result<Vec<UrlResponse>, String>>
            // so we have to unpack each Result and concatenate all the
            // Vec<UrlResponse>
            for response_result in responses_results {
                if response_result.is_ok() {
                    let response = response_result.unwrap();
                    responses.push(response);
                }
            }
        }

        Ok(responses)
    }

    /// Sends one HTTP request and get the response.
    async fn http_request(
        &self,
        url_request: &UrlRequest,
        http_client: &Client,
        request_type: UrlRequestType,
    ) -> Result<UrlResponse, String> {
        trace!("Running HttpReader::http_request()");
        let response_result = http_client
            .get(&url_request.url)
            .header("User-Agent", "Sanca")
            .header("Accept", "text/html")
            .send()
            .await;

        if let Err(e) = response_result {
            error!(
                "An error occured in the HTTP request to {}: {:?}",
                url_request.url, e
            );
            return Err(format!(
                "Error while sending an HTTP request to {}: {:?}",
                url_request.url, e
            ));
        }

        let response = response_result.unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();
        trace!("Extracting HTTP headers");
        for (header_name, header_value) in response.headers().iter() {
            // Only the first letter of the header name is in uppercase
            // It will avoid struggling with the case later
            let mut header_name_text = header_name.to_string().to_lowercase();
            header_name_text
                .get_mut(0..1)
                .unwrap()
                .make_ascii_uppercase();
            headers.insert(
                header_name_text,
                header_value.to_str().unwrap_or("").to_string(),
            );
        }

        let body = response.text().await.unwrap_or("".to_string());

        Ok(UrlResponse::new(
            &url_request.url,
            headers,
            &body,
            request_type,
        ))
    }

    /// Extract all URLs from a given string, and return them optionnally
    /// filtered on the given extension.
    /// It can be used to extract only JavaScript or CSS files.
    ///
    /// Note: the extension MUST contain the dot: ".js", ".css" etc
    pub fn extract_urls(
        &self,
        request_url: &str,
        data: &str,
        extension: Option<&str>,
    ) -> Vec<UrlRequest> {
        let mut url_requests: Vec<UrlRequest> = Vec::new();
        let caps = self.url_regex.captures_iter(data);
        for rmatch in caps {
            let mut url_or_path = rmatch.name("url").unwrap().as_str().to_string();
            let found_protocol = rmatch.name("protocol");
            let hostname = rmatch.name("hostname");
            // URL is in the following form: //www.this.com/a/b.js
            // It's used when we want to use the same protocol as the original request
            if found_protocol.is_none() && hostname.is_some() {
                let protocol = if request_url.starts_with("http://") {
                    "http:"
                } else {
                    "https:"
                };
                url_or_path = format!("{}{}", protocol, url_or_path);
            }
            let path_extension_match = rmatch.name("extension");
            let mut path_extension = "";
            if path_extension_match.is_some() {
                path_extension = path_extension_match.unwrap().as_str();
            }

            // If an extension has been provided, ignore the other ones
            if extension.is_some() && extension.unwrap() != path_extension {
                continue;
            }

            if url_or_path.starts_with("https://") || url_or_path.starts_with("http://") {
                url_requests.push(UrlRequest::new(&url_or_path, false));
            } else {
                url_requests.push(UrlRequest::from_path(request_url, &url_or_path, false));
            }
        }
        url_requests
    }
}
