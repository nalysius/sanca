//! The main module of Sanca
//!
//! This module defines the struct [`Application`], which orchestrates the execution
//! of the whole application.
//!
//! Sanca is composed of three parts:
//! 1. The [`crate::readers`]
//! 2. The [`crate::checkers`]
//! 3. The [`crate::writers`]
//!
//! The readers have the responsibility to fetch the data, be it a TCP banner
//! or HTTP resource(s).
//! The checkers have the role to match the data fetched by the readers against
//! regular expression, fingerprints or more, to confirm whether a given
//! technology is used by the remote host.
//! The writers are there to handle the findings returned by the checkers. They
//! can write them to standard output or in a CSV file for example.

use clap::{Parser, ValueEnum};

use crate::checkers::angular::AngularChecker;
use crate::checkers::angularjs::AngularJSChecker;
use crate::checkers::bootstrap::BootstrapChecker;
use crate::checkers::ckeditor::CKEditorChecker;
use crate::checkers::dovecot::DovecotChecker;
use crate::checkers::drupal::DrupalChecker;
use crate::checkers::exim::EximChecker;
use crate::checkers::gsap::GsapChecker;
use crate::checkers::handlebars::HandlebarsChecker;
use crate::checkers::highcharts::HighchartsChecker;
use crate::checkers::httpd::ApacheHttpdChecker;
use crate::checkers::jira::JiraChecker;
use crate::checkers::jquery::JQueryChecker;
use crate::checkers::jqueryui::JQueryUIChecker;
use crate::checkers::lodash::LodashChecker;
use crate::checkers::mariadb::MariaDBChecker;
use crate::checkers::melis::MelisChecker;
use crate::checkers::mysql::MySQLChecker;
use crate::checkers::nginx::NginxChecker;
use crate::checkers::openssh::OpenSSHChecker;
use crate::checkers::openssl::OpenSSLChecker;
use crate::checkers::os::OSChecker;
use crate::checkers::phonesystem_3cx::PhoneSystem3CXChecker;
use crate::checkers::php::PHPChecker;
use crate::checkers::phpmyadmin::PhpMyAdminChecker;
use crate::checkers::plesk::PleskChecker;
use crate::checkers::prestashop::PrestashopChecker;
use crate::checkers::proftpd::ProFTPDChecker;
use crate::checkers::pureftpd::PureFTPdChecker;
use crate::checkers::reactjs::ReactJSChecker;
use crate::checkers::squirrel_mail::SquirrelMailChecker;
use crate::checkers::symfony::SymfonyChecker;
use crate::checkers::tinymce::TinyMCEChecker;
use crate::checkers::tomcat::TomcatChecker;
use crate::checkers::twisted::TwistedChecker;
use crate::checkers::twistedweb::TwistedWebChecker;
use crate::checkers::typo3::Typo3Checker;
use crate::checkers::wordpress::WordPressChecker;
use crate::checkers::wp_plugins::akismet::AkismetChecker;
use crate::checkers::wp_plugins::all_in_one_seo::AllInOneSEOChecker;
use crate::checkers::wp_plugins::all_in_one_wp_migration::AllInOneWpMigrationChecker;
use crate::checkers::wp_plugins::classic_editor::ClassicEditorChecker;
use crate::checkers::wp_plugins::contact_form::ContactFormChecker;
use crate::checkers::wp_plugins::elementor::ElementorChecker;
use crate::checkers::wp_plugins::elements_ready_lite::ElementsReadyLiteChecker;
use crate::checkers::wp_plugins::forminator::ForminatorChecker;
use crate::checkers::wp_plugins::gtranslate::GTranslateChecker;
use crate::checkers::wp_plugins::jetpack::JetpackChecker;
use crate::checkers::wp_plugins::js_composer::JSComposerChecker;
use crate::checkers::wp_plugins::layerslider::LayerSliderChecker;
use crate::checkers::wp_plugins::litespeed_cache::LiteSpeedCacheChecker;
use crate::checkers::wp_plugins::mailchimp_for_wp::Mc4wpChecker;
use crate::checkers::wp_plugins::really_simple_ssl::ReallySimpleSSLChecker;
use crate::checkers::wp_plugins::revslider::RevSliderChecker;
use crate::checkers::wp_plugins::spectra::SpectraChecker;
use crate::checkers::wp_plugins::woocommerce::WooCommerceChecker;
use crate::checkers::wp_plugins::wordfence::WordfenceChecker;
use crate::checkers::wp_plugins::wp_mail_smtp::WpMailSmtpChecker;
use crate::checkers::wp_plugins::wp_members::WpMembersChecker;
use crate::checkers::wp_plugins::wpforms_lite::WpformsLiteChecker;
use crate::checkers::wp_plugins::yoast_seo::YoastSEOChecker;
use crate::checkers::wp_themes::divi::DiviChecker;
use crate::checkers::{HttpChecker, TcpChecker};
use crate::models::{reqres::UrlRequest, technology::Technology, Finding, ScanType, Writers};
use crate::readers::http::HttpReader;
use crate::readers::tcp::TcpReader;
use crate::writers::csv::CsvWriter;
use crate::writers::textstdout::TextStdoutWriter;
use crate::writers::Writer;

use log::{debug, error, info, trace};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
        trace!("In Application::new()");
        trace!("About to create the tcp_checkers list");
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

        trace!("About to create http_checkers list");
        let http_checkers: Vec<Box<dyn HttpChecker>> = vec![
            Box::new(OSChecker::new()),
            Box::new(ApacheHttpdChecker::new()),
            Box::new(JiraChecker::new()),
            Box::new(MelisChecker::new()),
            Box::new(NginxChecker::new()),
            Box::new(OpenSSLChecker::new()),
            Box::new(PhoneSystem3CXChecker::new()),
            Box::new(PHPChecker::new()),
            Box::new(PhpMyAdminChecker::new()),
            Box::new(PleskChecker::new()),
            Box::new(SquirrelMailChecker::new()),
            Box::new(SymfonyChecker::new()),
            Box::new(TomcatChecker::new()),
            Box::new(TwistedChecker::new()),
            Box::new(TwistedWebChecker::new()),
            Box::new(DrupalChecker::new()),
            Box::new(PrestashopChecker::new()),
            Box::new(Typo3Checker::new()),
            Box::new(WordPressChecker::new()),
            Box::new(AkismetChecker::new()),
            Box::new(AllInOneWpMigrationChecker::new()),
            Box::new(AllInOneSEOChecker::new()),
            Box::new(ClassicEditorChecker::new()),
            Box::new(ContactFormChecker::new()),
            Box::new(ElementorChecker::new()),
            Box::new(ElementsReadyLiteChecker::new()),
            Box::new(ForminatorChecker::new()),
            Box::new(DiviChecker::new()),
            Box::new(GTranslateChecker::new()),
            Box::new(JetpackChecker::new()),
            Box::new(JSComposerChecker::new()),
            Box::new(LayerSliderChecker::new()),
            Box::new(LiteSpeedCacheChecker::new()),
            Box::new(Mc4wpChecker::new()),
            Box::new(ReallySimpleSSLChecker::new()),
            Box::new(RevSliderChecker::new()),
            Box::new(SpectraChecker::new()),
            Box::new(WooCommerceChecker::new()),
            Box::new(WordfenceChecker::new()),
            Box::new(WpformsLiteChecker::new()),
            Box::new(WpMailSmtpChecker::new()),
            Box::new(WpMembersChecker::new()),
            Box::new(YoastSEOChecker::new()),
            Box::new(AngularChecker::new()),
            Box::new(AngularJSChecker::new()),
            Box::new(BootstrapChecker::new()),
            Box::new(CKEditorChecker::new()),
            Box::new(GsapChecker::new()),
            Box::new(HandlebarsChecker::new()),
            Box::new(HighchartsChecker::new()),
            Box::new(JQueryChecker::new()),
            Box::new(JQueryUIChecker::new()),
            Box::new(LodashChecker::new()),
            Box::new(ReactJSChecker::new()),
            Box::new(TinyMCEChecker::new()),
        ];

        trace!("Returning the Application");
        Application {
            tcp_checkers,
            http_checkers,
            argv: None,
        }
    }

    /// Read argv to get the arguments before running the application
    pub fn read_argv(&mut self) {
        trace!("In Application::read_argv()");
        let mut args = Args::parse();
        // For a TCP or UDP scan these two arguments are required
        // TODO: manage this with clap
        if (args.scan_type == ScanType::Tcp || args.scan_type == ScanType::Udp)
            && (args.ip_hostname.is_none() || args.port.is_none())
        {
            error!("Invalid parameters");
            error!(
                "Scan type = {:?}, IP/Hostname = {:?}, Port = {:?}",
                args.scan_type, args.ip_hostname, args.port
            );
            println!("Invalid parameters provided. Use sanca --help");
            panic!("To perform a TCP or UDP scan, the scan type, ip or hostname, and the port are required.");
        } else if args.scan_type == ScanType::Http && args.url.is_none() {
            error!("Invalid parameters, scan type is HTTP but no URL has been provided");
            // If a HTTP scan is asked but no URL has been provided
            println!("Invalid parameters provided. Use sanca --help");
            panic!("To perform a HTTP scan, the url is required.");
        } else if args.technologies.is_none() {
            debug!("No technologies specified, default to all");
            // If no technologies are provided, check for all
            args.technologies = Some(Technology::value_variants().to_vec());
        }
        // Filter on technologies supporting the given type of scan
        // It's not needed to check for Exim or ProFTPd in a HTTP scan
        debug!("Filtering technologies based on scan type");
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

        trace!(
            "These technologies are selected: {:?}",
            args.technologies.as_ref().unwrap()
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
        trace!("In Application::tcp_urp_scan()");
        let mut findings: Vec<Finding> = Vec::new();
        if scan_type == ScanType::Tcp {
            debug!("Starting a TCP scan");
            let tcp_reader = TcpReader::new(ip_hostname, port);
            let banner_result = tcp_reader.read(200);

            if let Err(e) = banner_result {
                error!("Unable to read the TCP banner: {:?}", e);
                panic!("Unable to read. {:?}", e);
            } else {
                let banner = banner_result.unwrap();
                info!("Here is the banner: {}", banner);
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
            debug!("Starting a UDP scan");
            panic!("UDP is not supported yet.");
        }
        return findings;
    }

    /// Performs a HTTP scan on a given set of UrlRequest
    fn http_scan(
        &self,
        url_requests: &[UrlRequest],
        technologies: &[Technology],
        user_agent: &str,
    ) -> Vec<Finding> {
        trace!("Performing a HTTP scan");
        let tk_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let http_reader = HttpReader::new();
        trace!("Sending the HTTP requests...");
        // Wait for all the HTTP requests to be finished
        let url_responses = tk_runtime.block_on(http_reader.read(&url_requests, user_agent));

        trace!("HTTP requests sent");
        trace!("Looping over all HTTP checkers");
        let mut findings = Vec::new();
        for http_checker in &self.http_checkers {
            trace!("HTTP checker -> {:?}", http_checker.get_technology());
            // Only use the current checker if it checks for one of the
            // technologies we're looking for
            if technologies.contains(&http_checker.get_technology()) {
                debug!("Using HTTP checker {:?}", http_checker.get_technology());
                let found_findings = http_checker.check_http(&url_responses);
                if !found_findings.is_empty() {
                    info!(
                        "HTTP checker {:?} found finding(s)",
                        http_checker.get_technology()
                    );
                    // Avoid storing duplicate findings
                    // That's especially for JavaScript libraries with plugins,
                    // that could be detected several times in different files.
                    for found_finding in found_findings {
                        if !findings.contains(&found_finding) {
                            findings.push(found_finding);
                        }
                    }
                }
            }
        }
        findings
    }

    /// Prints the header of the program.
    pub fn print_header(&self) {
        println!("Sanca software v{} - https://www.sanca.io\n", VERSION);
    }

    /// Runs the global application
    /// read_argv() MUST have been called before
    pub fn run(&self) {
        trace!("Running Application::run()");

        let args = self
            .argv
            .as_ref()
            .expect("CLI arguments haven't been read.");

        if !args.hide_header && Writers::TextStdout == args.writer {
            trace!("Showing header");
            self.print_header();
        }

        trace!("Checking args.scan_type");
        let findings: Vec<Finding> = match args.scan_type {
            ScanType::Tcp | ScanType::Udp => {
                info!("Scan type is TCP or UDP");
                let ip_hostname = &args.ip_hostname.clone().unwrap();
                let port = args.port.clone().unwrap();
                let scan_type = args.scan_type.clone();
                trace!(
                    "ip_hostname = {}, port = {}, scan_type = {:?}",
                    ip_hostname,
                    port,
                    scan_type
                );
                self.tcp_udp_scan(
                    &ip_hostname,
                    port,
                    scan_type,
                    &args.technologies.as_ref().unwrap(),
                )
            }
            ScanType::Http => {
                info!("Scan type is HTTP");
                let url_requests = UrlRequest::from_technologies(
                    &args.url.as_ref().unwrap(),
                    &args.technologies.as_ref().unwrap(),
                );
                debug!("URL requests: {:?}", url_requests);
                self.http_scan(
                    &url_requests,
                    &args.technologies.as_ref().unwrap(),
                    &args.user_agent,
                )
            }
        };

        info!("Scan finished, writing output");
        let writer: Box<dyn Writer> = match args.writer {
            Writers::TextStdout => Box::new(TextStdoutWriter::new(args)),
            Writers::Csv => Box::new(CsvWriter::new(args)),
        };
        writer.write(findings);
    }
}

/// Represents the CLI arguments accepted by Sanca
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
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
    /// The technologies to check
    #[arg(short, long, value_name = "TECHNOLOGIES")]
    pub technologies: Option<Vec<Technology>>,
    /// The writer to use
    #[arg(short, long, value_name = "WRITER", default_value = "textstdout")]
    pub writer: Writers,
    /// The user agent
    #[arg(short('a'), long, value_name = "USER_AGENT", default_value = "Sanca")]
    pub user_agent: String,
    /// Hide the header with the URL to the Sanca's website
    #[arg(short('e'), long)]
    pub hide_header: bool,
}
