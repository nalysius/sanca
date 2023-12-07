//! The module related to technologies.
//!
//! A [`Technology`] is a generic term to name a software, a programming
//! language, a web server, a JavaScript library, a CMS and more.
//!
//! It's possible to instruct Sanca to search only for a given set of
//! technologies. It's mainly useful in HTTP scan, since it allows to
//! send less requests.

use super::reqres::UrlRequest;
use super::ScanType;
use clap::{builder::PossibleValue, ValueEnum};

/// An enumeration to represent the technologies that Sanca can tried to identify.
/// In practice it is useful mainly for the web technologies to send only
/// HTTP requests needed to identify the given technologies.
/// As an example, it's not needed to send a request at /phpinfo.php
/// if we want to identify only the JavaScript libraries.
#[derive(Clone, PartialEq, Debug)]
pub enum Technology {
    Dovecot,
    Exim,
    MariaDB,
    MySQL,
    OpenSSH,
    ProFTPD,
    PureFTPd,
    /// OS is generic for all OSes.
    OS,
    PHP,
    PhpMyAdmin,
    Typo3,
    WordPress,
    Drupal,
    /// Apache httpd
    Httpd,
    Tomcat,
    Nginx,
    OpenSSL,
    JQuery,
    ReactJS,
    Handlebars,
    Lodash,
    AngularJS,
    Gsap,
    Bootstrap,
    Angular,
    Plesk,
    CKEditor,
    Highcharts,
    // WPP = WordPress Plugin
    WPPYoastSEO,
    WPPRevSlider,
    WPPJSComposer,
    WPPContactForm,
    Melis,
}

impl Technology {
    /// Returns the scan types matching the technology
    /// Most technologies are HTTP-related, so define only the
    /// specific-ones
    pub fn get_scans(&self) -> Vec<ScanType> {
        match self {
            Self::Dovecot | Self::Exim => vec![ScanType::Tcp],
            Self::MariaDB | Self::MySQL => vec![ScanType::Tcp],
            Self::OpenSSH | Self::ProFTPD | Self::PureFTPd => vec![ScanType::Tcp],
            Self::OS => vec![ScanType::Tcp, ScanType::Http],
            // Most technologies are about HTTP, so specify only the TCP, UDP
            // or multiple scan types, the rest will be HTTP-only
            _ => vec![ScanType::Http],
        }
    }

    /// Checks whether the technology supports the given scan type
    ///
    /// # Examples
    ///
    /// ```rust
    /// let technology = sanca::models::technology::Technology::OpenSSH;
    /// assert!(technology.supports_scan(sanca::models::ScanType::Tcp));
    /// ```
    pub fn supports_scan(&self, scan_type: ScanType) -> bool {
        self.get_scans().contains(&scan_type)
    }

    /// Get the HTTP paths to request for a given technology
    ///
    /// For non-HTTP scans, an empty list is returned. For HTTP scans,
    /// the requests matching the technology are returned.
    pub fn get_url_requests(&self, main_url: &str) -> Vec<UrlRequest> {
        // Non-HTTP technologies don't need any paths
        if !self.supports_scan(ScanType::Http) {
            return Vec::new();
        }

        match self {
            Self::PHP => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "/phpinfo.php", false),
                    UrlRequest::from_path(main_url, "/info.php", false),
                    UrlRequest::from_path(main_url, "phpinfo.php", false),
                    UrlRequest::from_path(main_url, "info.php", false),
                    UrlRequest::from_path(main_url, "/pageNotFoundNotFound", false),
                    UrlRequest::from_path(main_url, "/phpmyadmin/", false),
                ]
            }
            Self::Httpd | Self::Nginx | Self::OpenSSL => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "/pageNotFoundNotFound", false),
                    UrlRequest::from_path(main_url, "/phpmyadmin/", false),
                ]
            }
            Self::Tomcat => {
                vec![UrlRequest::from_path(
                    main_url,
                    "/pageNotFoundNotFound",
                    false,
                )]
            }
            Self::PhpMyAdmin => {
                vec![
                    UrlRequest::from_path(main_url, "doc/html/index.html", false),
                    UrlRequest::from_path(main_url, "/phpmyadmin/doc/html/index.html", false),
                    UrlRequest::from_path(main_url, "/mysql/doc/html/index.html", false),
                    UrlRequest::from_path(main_url, "ChangeLog", false),
                ]
            }
            Self::Typo3 => {
                vec![
                    UrlRequest::from_path(main_url, "typo3/sysext/install/composer.json", false),
                    UrlRequest::from_path(
                        main_url,
                        "typo3/sysext/linkvalidator/composer.json",
                        false,
                    ),
                ]
            }
            Self::WordPress => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "wp-login.php", false),
                ]
            }
            Self::Plesk => {
                vec![UrlRequest::from_path(main_url, "/login_up.php", false)]
            }
            Self::WPPContactForm => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/contact-form-7/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/contact-form-7/readme.txt",
                        false,
                    ),
                ]
            }
            Self::Melis => {
                vec![UrlRequest::from_path(main_url, "/melis/login", false)]
            }
            _ => vec![UrlRequest::new(main_url, true)],
        }
    }
}

impl ValueEnum for Technology {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Technology::Dovecot,
            Technology::Exim,
            Technology::MariaDB,
            Technology::MySQL,
            Technology::OpenSSH,
            Technology::ProFTPD,
            Technology::PureFTPd,
            Technology::OS,
            Technology::PHP,
            Technology::PhpMyAdmin,
            Technology::WordPress,
            Technology::Drupal,
            Technology::Typo3,
            Technology::Httpd,
            Technology::Nginx,
            Technology::OpenSSL,
            Technology::JQuery,
            Technology::ReactJS,
            Technology::Handlebars,
            Technology::Lodash,
            Technology::AngularJS,
            Technology::Gsap,
            Technology::Tomcat,
            Technology::Bootstrap,
            Technology::Angular,
            Technology::Plesk,
            Technology::CKEditor,
            Technology::Highcharts,
            Technology::WPPYoastSEO,
            Technology::WPPRevSlider,
            Technology::WPPJSComposer,
            Technology::WPPContactForm,
            Technology::Melis,
        ]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            Technology::Dovecot => Some(PossibleValue::new("dovecot")),
            Technology::Exim => Some(PossibleValue::new("exim")),
            Technology::MariaDB => Some(PossibleValue::new("mariadb")),
            Technology::MySQL => Some(PossibleValue::new("mysql")),
            Technology::OpenSSH => Some(PossibleValue::new("openssh")),
            Technology::ProFTPD => Some(PossibleValue::new("proftpd")),
            Technology::PureFTPd => Some(PossibleValue::new("pureftpd")),
            Technology::OS => Some(PossibleValue::new("os")),
            Technology::PHP => Some(PossibleValue::new("php")),
            Technology::PhpMyAdmin => Some(PossibleValue::new("phpmyadmin")),
            Technology::WordPress => Some(PossibleValue::new("wordpress")),
            Technology::Drupal => Some(PossibleValue::new("drupal")),
            Technology::Typo3 => Some(PossibleValue::new("typo3")),
            Technology::Httpd => Some(PossibleValue::new("httpd")),
            Technology::Tomcat => Some(PossibleValue::new("tomcat")),
            Technology::Nginx => Some(PossibleValue::new("nginx")),
            Technology::OpenSSL => Some(PossibleValue::new("openssl")),
            Technology::JQuery => Some(PossibleValue::new("jquery")),
            Technology::ReactJS => Some(PossibleValue::new("reactjs")),
            Technology::Handlebars => Some(PossibleValue::new("handlebars")),
            Technology::Lodash => Some(PossibleValue::new("lodash")),
            Technology::AngularJS => Some(PossibleValue::new("angularjs")),
            Technology::Gsap => Some(PossibleValue::new("gsap")),
            Technology::Bootstrap => Some(PossibleValue::new("bootstrap")),
            Technology::Angular => Some(PossibleValue::new("angular")),
            Technology::Plesk => Some(PossibleValue::new("plesk")),
            Technology::CKEditor => Some(PossibleValue::new("ckeditor")),
            Technology::Highcharts => Some(PossibleValue::new("highcharts")),
            Technology::WPPYoastSEO => Some(PossibleValue::new("yoastseo")),
            Technology::WPPRevSlider => Some(PossibleValue::new("revslider")),
            Technology::WPPJSComposer => Some(PossibleValue::new("jscomposer")),
            Technology::WPPContactForm => Some(PossibleValue::new("contactform")),
            Technology::Melis => Some(PossibleValue::new("melis")),
        }
    }
}
