//! Write the [`Finding`]s as JSON
//! It presents the findings in a JSON format and prints it on STDOUT.

use super::Writer;
use crate::{
    application::Args,
    models::{reqres::UrlRequest, Finding},
};
use serde_json::json;

/// A writer to print the findings as JSON.
pub struct JsonWriter {
    /// The IP of hostname scanned
    ip_hostname: Option<String>,
    /// The port scanned
    port: Option<u16>,
    /// The URL scanned
    url: Option<String>,
}

impl Writer for JsonWriter {
    /// Create a new JsonWriter
    fn new(argv: &Args) -> Self {
        let mut new_ip_hostname = argv.ip_hostname.clone();
        let mut new_port = argv.port;
        let url = argv.url.clone();

        // If scan type is HTTP, we have the URL but no ip_hostname nor port.
        // define them from the URL
        if url.is_some() {
            let url_request = UrlRequest::new(argv.url.as_ref().unwrap(), false);
            let (tmp_hostname, tmp_port) = url_request.get_hostname_port();
            new_ip_hostname = Some(tmp_hostname);
            new_port = Some(tmp_port);
        }

        Self {
            ip_hostname: new_ip_hostname,
            port: new_port,
            url: url,
        }
    }

    /// Writes the findings
    fn write(&self, findings: Vec<Finding>) {
        // TODO: Add an object to contain ip_hostname & port
        // { ip_hostname: "example.org", port: 25, findings: [...]  }
        println!("{}", json!(findings));
    }
}
