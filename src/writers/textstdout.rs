//! Write the [`Finding`]s to standard output
//! It is the default writer, it presents the findings in a text
//! format and prints it on STDOUT.

use super::Writer;
use crate::{application::Args, models::Finding};

/// A writer to print the findings in the terminal.
pub struct TextStdoutWriter {
    /// The IP of hostname scanned
    ip_hostname: Option<String>,
    /// The port scanned
    port: Option<u16>,
    /// The URL scanned
    url: Option<String>,
}

impl Writer for TextStdoutWriter {
    /// Create a new TextStdoutWriter
    fn new(argv: &Args) -> Self {
        Self {
            ip_hostname: argv.ip_hostname.clone(),
            port: argv.port,
            url: argv.url.clone(),
        }
    }

    /// Prints the findings on STDOUT
    fn write(&self, findings: Vec<Finding>) {
        let title;
        if self.url.is_some() {
            title = self.url.as_ref().unwrap().to_string();
        } else if self.ip_hostname.is_some() && self.port.is_some() {
            title = format!(
                "{}:{}",
                self.ip_hostname.as_ref().unwrap(),
                self.port.unwrap()
            );
        } else {
            panic!("The text writer didn't receive valid parameters");
        }

        println!("----------{}----------\n", title);
        for finding in findings {
            let mut version = "unknown";
            if finding.version.is_some() {
                version = &finding.version.as_ref().unwrap();
            }
            let mut cve_ids = Vec::new();
            for vuln in finding.vulnerabilities {
                cve_ids.push(vuln.cve_id);
            }

            let cve_str = if cve_ids.len() > 0 {
                format!(" | CVE: {}", cve_ids.join(", "))
            } else {
                String::new()
            };

            println!(
                "[{}/{}] {}{}\n",
                finding.technology.to_string(),
                version,
                finding.evidence_text,
                cve_str
            );
        }
    }
}
