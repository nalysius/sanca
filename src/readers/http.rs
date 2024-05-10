//! Fetch data over HTTP(S)
//!
//! The [`HttpReader`] is there to fetch resources via HTTP(S), to identify the
//! technologies being used by the remote host.

use std::collections::HashMap;

use futures::future::join_all;
use log::{debug, error, info, trace};
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
pub struct HttpReader<'a> {
    /// The regex to find URLs
    url_regexes: HashMap<&'a str, Regex>,
}

impl HttpReader<'_> {
    /// Creates a new HttpReader
    pub fn new() -> Self {
        let script_regex = Regex::new(
            r#"<script[^>]+src\s*=\s*["']?\s*(?P<url>(((?P<protocol>[a-z0-9]+):)?\/\/(?P<hostname>[^\/:]+)(:(?P<port>\d{1,5}))?)?(?P<path>\/?[a-zA-Z0-9\/._ %@-]*(?P<extension>\.[a-zA-Z0-9_-]+)?)?(?P<querystring>\?[^#\s'">]*)?(#[^'">\s]*)?)\s*["']?"#
        ).unwrap();

        // Example: Sfjs.loadToolbar('c32ea2')
        let symfony_debug_toolbar_regex = Regex::new(
            r#"<script[^>]*>.*Sfjs.loadToolbar\(['"](?P<profilertoken>[a-f0-9]+)['"]\)"#,
        )
        .unwrap();

        // Old Symfony (e.g.: 3.x) use this form instead
        //
        // Example: Sfjs.load('sfwdte16009', '\/app_dev.php\/_wdt\/e16009',
        let symfony_old_debug_toolbar_regex =
            Regex::new(r#"Sfjs\.load\(\s*['"]sfwdt(?P<profilertoken>[a-f0-9]+)['"]"#).unwrap();

        let mut url_regexes = HashMap::new();
        url_regexes.insert("scripts", script_regex);
        url_regexes.insert("symfony_debug_toolbar", symfony_debug_toolbar_regex);
        url_regexes.insert("symfony_old_debug_toolbar", symfony_old_debug_toolbar_regex);
        HttpReader {
            url_regexes: url_regexes,
        }
    }

    /// Reads via HTTP(S)
    /// Sends HTTP requests to each URL to fetch the response, and
    /// optionally requests the JavaScript files found in the response body.
    pub async fn read(&self, url_requests: &[UrlRequest], user_agent: &str) -> Vec<UrlResponse> {
        trace!("Running HttpReader::read()");
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Unable to create a HTTP client.");

        // Here we store all the Futures of the http requests
        // They will be handled all together in parallel
        let mut url_responses_futures = Vec::new();

        for url_request in url_requests {
            trace!(
                "Pushing {} / fetch_js = {} to the list of UrlRequests to fetch",
                url_request.url,
                url_request.fetch_js
            );
            url_responses_futures.push(self.read_one_page(url_request, &http_client, user_agent));
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
        user_agent: &str,
    ) -> Result<Vec<UrlResponse>, String> {
        trace!("Running HttpChecker::read_one_page()");
        debug!("Sending HTTP request for URL {}", url_request.url);
        let mut responses: Vec<UrlResponse> = Vec::new();
        let main_response_result = self
            .http_request(
                &url_request,
                http_client,
                UrlRequestType::Default,
                user_agent,
            )
            .await;
        if let Err(e) = main_response_result {
            error!("An error occured while reading one page: {:?}", e);
            return Err(e);
        }

        trace!("Pushing the HTTP response to the list");
        let main_response = main_response_result.unwrap();
        let main_response_body = main_response.body.clone();
        responses.push(main_response);

        let mut next_urls_requests = Vec::new();
        if url_request.fetch_js {
            debug!("Fetch JS is true for URL {}", url_request.url);
            next_urls_requests =
                self.extract_urls(&url_request.url, &main_response_body, None, "scripts");
            info!(
                "The following URLs have been found in the response body: {:?}",
                next_urls_requests
            );
        }

        // Search if the Symfony toolbar is present on the page. If so, generate
        // a UrlRequest for the profiler
        let url_requests_symfony = self.extract_symfony(&url_request.url, &main_response_body);
        if url_requests_symfony.is_some() {
            next_urls_requests.push(url_requests_symfony.unwrap());
        }

        // Here we store all the Futures of the http requests
        // They will be handled all together in parallel
        let url_responses_futures = next_urls_requests.iter().map(|i| {
            let request_type = if i.fetch_js {
                UrlRequestType::JavaScript
            } else {
                UrlRequestType::Default
            };

            let response_future = self.http_request(&i, &http_client, request_type, user_agent);
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

        Ok(responses)
    }

    /// Sends one HTTP request and get the response.
    async fn http_request(
        &self,
        url_request: &UrlRequest,
        http_client: &Client,
        request_type: UrlRequestType,
        user_agent: &str,
    ) -> Result<UrlResponse, String> {
        trace!("Running HttpReader::http_request()");
        let mime_type = "text/html,application/javascript,*/*;q=0.8";
        let response_result = http_client
            .get(&url_request.url)
            .header("User-Agent", user_agent)
            .header("Accept", mime_type)
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

            // When a header is given several times (e.g. x-powered-by), concatenate
            if headers.contains_key(&header_name_text) {
                let concat_header = format!(
                    "{}, {}",
                    headers.get(&header_name_text).unwrap(),
                    header_value.to_str().unwrap_or("").to_string(),
                );

                headers.insert(header_name_text, concat_header);
            } else {
                headers.insert(
                    header_name_text,
                    header_value.to_str().unwrap_or("").to_string(),
                );
            }
        }

        let status_code = response.status().as_u16();
        // In case of redirection, the final URL will be stored & printed
        let response_url = response.url().to_string();
        let body = response.text().await.unwrap_or("".to_string());

        Ok(UrlResponse::new(
            &response_url,
            headers,
            &body,
            request_type,
            status_code,
        ))
    }

    /// Extract all URLs from a given string, and return them optionnally
    /// filtered on the given extension.
    /// It can be used to extract only JavaScript or CSS files.
    pub fn extract_urls(
        &self,
        request_url: &str,
        data: &str,
        extension: Option<&str>,
        regex_name: &str,
    ) -> Vec<UrlRequest> {
        let mut url_requests: Vec<UrlRequest> = Vec::new();

        let caps = self
            .url_regexes
            .get(regex_name)
            .unwrap()
            .captures_iter(data);
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

    /// Search the Symfony toolbar and if found, return a UrlRequest to
    /// find the Symfony version.
    pub fn extract_symfony(&self, url: &str, data: &str) -> Option<UrlRequest> {
        let regex_names = ["symfony_debug_toolbar", "symfony_old_debug_toolbar"];
        for regex_name in regex_names {
            let caps = self
                .url_regexes
                .get(regex_name)
                .unwrap()
                .captures_iter(data);
            for rmatch in caps {
                let token = rmatch.name("profilertoken");
                if token.is_some() {
                    // Old Symfony used app_dev.php for debug mode, in paths like
                    // /app_dev.php/_profiler/xxxxxx?panel=config
                    // The UrlRequest::from_path method works on relative path as
                    // on directories, so the generated URL would be /_profiler/[...]
                    // To prevent this, app a slash to the end.
                    let mut url_mut = url.to_string();
                    if regex_name == "symfony_old_debug_toolbar" {
                        url_mut = format!("{}/", url);
                    }
                    return Some(UrlRequest::from_path(
                        &url_mut,
                        &format!("_profiler/{}?panel=config", token.unwrap().as_str()),
                        false,
                    ));
                }
            }
        }

        return None;
    }
}
