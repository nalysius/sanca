//! This module contains the main structure and logic for the whole
//! application.

use clap::{Parser, ValueEnum};

use crate::checkers::dovecot::DovecotChecker;
use crate::checkers::exim::EximChecker;
use crate::checkers::handlebars::HandlebarsChecker;
use crate::checkers::httpd::ApacheHttpdChecker;
use crate::checkers::jquery::JQueryChecker;
use crate::checkers::mariadb::MariaDBChecker;
use crate::checkers::mysql::MySQLChecker;
use crate::checkers::nginx::NginxChecker;
use crate::checkers::openssh::OpenSSHChecker;
use crate::checkers::openssl::OpenSSLChecker;
use crate::checkers::os::OSChecker;
use crate::checkers::php::PHPChecker;
use crate::checkers::proftpd::ProFTPDChecker;
use crate::checkers::pureftpd::PureFTPdChecker;
use crate::checkers::{HttpChecker, TcpChecker};
use crate::models::{Finding, ScanType, Technology, UrlRequest};
use crate::readers::httpreader::HttpReader;
use crate::readers::tcpreader::TcpReader;
use crate::writers::textstdout::TextStdout;
use crate::writers::Writer;

/// Represents the application
pub struct Application {
    /// The list of TCP checkers available to the application.
    tcp_checkers: Vec<Box<dyn TcpChecker>>,
    /// The list of HTTP checkers available to the application.
    http_checkers: Vec<Box<dyn HttpChecker>>,
    /// The arguments given on the command line.
    argv: Option<Args>,
}

impl Application {
    /// Creates a new application
    pub fn new() -> Self {
        // When a new checker is created, it has to be instanciated here
        // to be used.
        let tcp_checkers: Vec<Box<dyn TcpChecker>> = vec![
            Box::new(OSChecker::new()),
            Box::new(ProFTPDChecker::new()),
            Box::new(PureFTPdChecker::new()),
            Box::new(OpenSSHChecker::new()),
            Box::new(EximChecker::new()),
            Box::new(DovecotChecker::new()),
            Box::new(MySQLChecker::new()),
            Box::new(MariaDBChecker::new()),
        ];

        let http_checkers: Vec<Box<dyn HttpChecker>> = vec![
            Box::new(OSChecker::new()),
            Box::new(ApacheHttpdChecker::new()),
            Box::new(NginxChecker::new()),
            Box::new(PHPChecker::new()),
            Box::new(OpenSSLChecker::new()),
            Box::new(JQueryChecker::new()),
            Box::new(HandlebarsChecker::new()),
        ];

        Application {
            tcp_checkers,
            http_checkers,
            argv: None,
        }
    }

    /// Read argv to get the arguments before running the application
    pub fn read_argv(&mut self) {
        let mut args = Args::parse();
        // For a TCP or UDP scan these two arguments are required
        // TODO: manage this with clap
        if (args.scan_type == ScanType::Tcp || args.scan_type == ScanType::Udp)
            && (args.ip_hostname.is_none() || args.port.is_none())
        {
            println!("Invalid parameters provided. Use sanca --help");
            panic!("To perform a TCP or UDP scan, the scan type, ip or hostname, and the port are required.");
        } else if args.scan_type == ScanType::Http && args.url.is_none() {
            // If a HTTP scan is asked but no URL has been provided
            println!("Invalid parameters provided. Use sanca --help");
            panic!("To perform a HTTP scan, the url is required.");
        } else if args.technologies.is_none() {
            // If no technologies are provided, check for all
            args.technologies = Some(Technology::value_variants().to_vec());
        }
        // Filter on technologies supporting the given type of scan
        // It's not needed to check for Exim or ProFTPd in a HTTP scan
        let scan_type = args.scan_type;
        args.technologies = Some(
            args.technologies
                .as_ref()
                .unwrap()
                .iter()
                .filter(|i| i.supports_scan(scan_type))
                .map(|i| i.to_owned())
                .collect(),
        );

        self.argv = Some(args);
    }

    /// Executes a TCP or UDP scan
    pub fn tcp_udp_scan(
        &self,
        ip_hostname: &str,
        port: u16,
        scan_type: ScanType,
        technologies: &[Technology],
    ) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        if scan_type == ScanType::Tcp {
            let tcp_reader = TcpReader::new(ip_hostname, port);
            let banner_result = tcp_reader.read(200);

            if let Err(e) = banner_result {
                panic!("Unable to read. {:?}", e);
            } else {
                let banner = banner_result.unwrap();
                for tcp_checker in &self.tcp_checkers {
                    // Use the current checker only if it supports one of the
                    // technologies we're looking for
                    if technologies.contains(&tcp_checker.get_technology()) {
                        let option_finding = tcp_checker.check_tcp(&[banner.clone()]);
                        if option_finding.is_some() {
                            findings.push(option_finding.unwrap());
                        }
                    }
                }
            }
        } else if scan_type == ScanType::Udp {
            panic!("UDP is not supported yet.");
        }
        return findings;
    }

    /// Performs a HTTP scan on a given set of UrlRequest
    fn http_scan(&self, url_requests: &[UrlRequest], technologies: &[Technology]) -> Vec<Finding> {
        let tk_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let http_reader = HttpReader::new();
        // Wait for all the HTTP requests to be finished
        let url_responses = tk_runtime.block_on(http_reader.read(&url_requests));

        let mut findings = Vec::new();
        for http_checker in &self.http_checkers {
            // Only use the current checker if it checks for one of the
            // technologies we're looking for
            if technologies.contains(&http_checker.get_technology()) {
                let finding = http_checker.check_http(&url_responses);
                if finding.is_some() {
                    findings.push(finding.unwrap());
                }
            }
        }
        findings
    }

    /// Runs the global application
    /// read_argv() MUST have been called before
    pub fn run(&self) {
        let args = self
            .argv
            .as_ref()
            .expect("CLI arguments haven't been read.");
        let findings: Vec<Finding> = match args.scan_type {
            ScanType::Tcp | ScanType::Udp => {
                let ip_hostname = &args.ip_hostname.clone().unwrap();
                let port = args.port.clone().unwrap();
                let scan_type = args.scan_type.clone();
                self.tcp_udp_scan(
                    &ip_hostname,
                    port,
                    scan_type,
                    &args.technologies.as_ref().unwrap(),
                )
            }
            ScanType::Http => {
                let url_requests = UrlRequest::from_technologies(
                    &args.url.as_ref().unwrap(),
                    &args.technologies.as_ref().unwrap(),
                );
                self.http_scan(&url_requests, &args.technologies.as_ref().unwrap())
            }
        };

        let writer = TextStdout::new(
            args.ip_hostname.clone(),
            args.port.clone(),
            args.url.clone(),
        );
        writer.write(findings);
    }
}

/// Represents the CLI arguments accepted by Sanca
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The URL where to send an HTTP request
    #[arg(short, long, value_name = "URL")]
    pub url: Option<String>,
    /// The IP or hostname to connect on
    #[arg(short, long, value_name = "IP_HOSTNAME")]
    pub ip_hostname: Option<String>,
    /// The port to connect on
    #[arg(short, long, value_name = "PORT")]
    pub port: Option<u16>,
    /// The type of scan
    #[arg(short, long, value_name = "SCAN_TYPE")]
    pub scan_type: ScanType,
    #[arg(short, long, value_name = "TECHNOLOGIES")]
    pub technologies: Option<Vec<Technology>>,
}
