//! This module declares a HTTP reader. The objective is to easily read
//! data over HTTP.

use std::collections::HashMap;

use futures::future::join_all;
use reqwest::Client;

use crate::models::{UrlRequest, UrlResponse};

/// A HTTP reader
pub struct HttpReader {}

impl HttpReader {
    /// Creates a new HttpReader
    pub fn new() -> Self {
        HttpReader {}
    }

    /// Reads via HTTP(S)
    /// Sends HTTP requests to each URL to fetch the response, and
    /// optionally requests the JavaScript files found in the response body.
    pub async fn read(&self, url_requests: &[UrlRequest]) -> Vec<UrlResponse> {
        let http_client = Client::new();

        // Here we store all the Futures of the http requests
        // They will be handled all together in parallel
        let mut url_responses_futures = Vec::new();

        for url_request in url_requests {
            url_responses_futures.push(self.read_one_page(url_request, &http_client));
        }

        // Send all the HTTP requests, and wait for the result
        let responses_results = join_all(url_responses_futures).await;
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
        let mut responses: Vec<UrlResponse> = Vec::new();
        let main_response_result = self.http_request(&url_request, http_client).await;
        if let Err(e) = main_response_result {
            return Err(e);
        }

        responses.push(main_response_result.unwrap());

        if url_request.fetch_js {
            // TODO: extract all JS files and fetch them
            // Avoid duplicates by checking if the Url is already known in our responses
        }

        Ok(responses)
    }

    /// Sends one HTTP request and get the response.
    async fn http_request(
        &self,
        url_request: &UrlRequest,
        http_client: &Client,
    ) -> Result<UrlResponse, String> {
        let response_result = http_client
            .get(&url_request.url)
            .header("User-Agent", "Sanca")
            .header("Accept", "text/html")
            .send()
            .await;

        if let Err(e) = response_result {
            return Err(format!(
                "Error while sending an HTTP request to {}: {:?}",
                url_request.url, e
            ));
        }

        let response = response_result.unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();
        for (header_name, header_value) in response.headers().iter() {
            headers.insert(
                header_name.to_string(),
                header_value.to_str().unwrap_or("").to_string(),
            );
        }

        let body = response.text().await.unwrap_or("".to_string());

        Ok(UrlResponse::new(&url_request.url, headers, &body))
    }
}

/// A struct to represent the result of an HTTP reader.
/// It contains everything that a checker could need.
pub struct HttpRequestResponse {
    /// The full URL where the HTTP request has been sent
    pub request_url: String,
    /// The HTTP headers of the response
    pub response_headers: HashMap<String, String>,
    /// The body of the HTTP response
    pub response_body: String,
    /// Whether it was the main request or a subsequent URL.
    /// In the body of /index.php we could find a lot of JavaScript files
    /// and decide to fetch them too. The JavaScript files would be subsequent
    /// requests, not main ones.
    pub is_main_request: bool,
}
