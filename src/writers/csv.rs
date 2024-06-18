//! Write the [`Finding`]s as CSV
//! It presents the findings in a CSV format and prints it on STDOUT.

use super::Writer;
use crate::{
    application::Args,
    models::{reqres::UrlRequest, Finding},
};

/// A writer to print the findings as CSV.
pub struct CsvWriter {
    /// The IP of hostname scanned
    ip_hostname: Option<String>,
    /// The port scanned
    port: Option<u16>,
    /// The URL scanned
    url: Option<String>,
}

impl Writer for CsvWriter {
    /// Create a new CsvWriter
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
        let mut csv = "\"Technology\",\"Version\",".to_string();

        // TCP or UDP scan (could be set in HTTP scan based on the URL)
        if self.ip_hostname.is_some() {
            csv.push_str("\"IP / Hostname\",\"Port\",")
        }
        // HTTP scan
        if self.url.is_some() {
            csv.push_str("\"Main URL\",\"URL of finding\",");
        }

        csv.push_str("\"Evidence\",\"Evidence text\", \"CVEs\"\n");
        for finding in findings {
            let mut version = "unknown";
            if finding.version.is_some() {
                version = &finding.version.as_ref().unwrap();
            }

            // Build the CSV line according to the scan type
            // Escape quotes (") to avoid breaking the CSV
            let mut csv_line = format!(
                "\"{}\",\"{}\",",
                finding.technology.to_string().replace("\"", "\"\""),
                version.replace("\"", "\"\"")
            );
            // TCP or UDP scan (could be set in HTTP scan based on the URL)
            if self.ip_hostname.is_some() {
                csv_line.push_str(&format!(
                    "\"{}\",\"{}\",",
                    self.ip_hostname.as_ref().unwrap().replace("\"", "\"\""),
                    self.port.unwrap()
                ));
            }
            // HTTP scan
            if self.url.is_some() {
                csv_line.push_str(&format!(
                    "\"{}\",\"{}\",",
                    self.url.as_ref().unwrap().replace("\"", "\"\""),
                    finding.url_of_finding.unwrap().replace("\"", "\"\"")
                ));
            }

            // Add the CVEs
            let mut cve_ids = Vec::new();
            for vuln in finding.vulnerabilities {
                cve_ids.push(vuln.cve_id);
            }

            csv_line.push_str(&format!(
                "\"{}\",\"{}\", \"{}\"\n",
                finding.evidence.replace("\"", "\"\""),
                finding.evidence_text.replace("\"", "\"\""),
                cve_ids.join(", ").replace("\"", "\"\"")
            ));
            csv.push_str(&csv_line);
        }
        println!("{}", csv);
    }
}
