//! This module contains the main structure and logic for the whole
//! application.

use crate::checkers::Checker;
use crate::checkers::openssh::OpenSSHChecker;
use crate::readers::tcpreader::TcpReader;
use crate::writers::Writer;
use crate::writers::textstdout::TextStdout;

/// Represents the application
pub struct Application {

}

impl Application {
    /// Creates a new application
    pub fn new() -> Self {
        Application {

        }
    }

    /// Prints the usage instructions
    pub fn show_usage(&self) {
        println!("Usage: ./sanca <ip_hostname> <port>");
        println!("Where <ip_hostname> is either the IP address or the hostname of the asset to scan");
        println!("and <port> the port to scan.");
    }

    /// Executes the application
    pub fn run(&self, ip_hostname: &str, port: u16) {
        // TODO: if tcp reader doesn't work, try UDP.
        // if tcp works but doesn't read anything, try HTTP.
        // Note: if the scan type or the technology is provided as CLI parameter,
        // use only this one
        let tcp_reader = TcpReader::new(ip_hostname, port);
        let banner_result = tcp_reader.read(30);

        if let Err(e) = banner_result {
            println!("Unable to read. {:?}", e);
        } else {
            println!("----------{}:{}----------\n", ip_hostname, port);
            let banner = banner_result.unwrap();
            // TODO: loop over all checkers, not only OpenSSH
            let openssh_checker = OpenSSHChecker::new();
            let findings = openssh_checker.check(&[banner]);
            let writer = TextStdout::new();
            writer.write(findings);           
        }
    }
}