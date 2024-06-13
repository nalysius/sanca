//! The module related to technologies.
//!
//! A [`Technology`] is a generic term to name a software, a programming
//! language, a web server, a JavaScript library, a CMS and more.
//!
//! It's possible to instruct Sanca to search only for a given set of
//! technologies. It's mainly useful in HTTP scan, since it allows to
//! send less requests.

use clap::{builder::PossibleValue, ValueEnum};
use std::fmt::{Display, Formatter};
use std::string::ToString;
use super::reqres::UrlRequest;
use super::ScanType;

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
    /// It can be given as CLI input (with -t), but the specific OSes,
    /// on the other hand, cannot be given as input, they can only be returned
    /// in findings.
    OS,
    Ubuntu,
    Debian,
    CentOS,
    Fedora,
    Unix,
    OracleLinux,
    FreeBSD,
    OpenBSD,
    NetBSD,
    AlmaLinux,
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
    WPPElementor,
    WPPElementsReadyLite,
    WPPGTranslate,
    WPPWooCommerce,
    // WPT = WordPress Theme
    WPTDivi,
    WPPClassicEditor,
    WPPAkismet,
    WPPWpformsLite,
    WPPAllInOneWpMigration,
    WPPReallySimpleSSL,
    WPPJetpack,
    WPPLiteSpeedCache,
    WPPAllInOneSEO,
    WPPWordfence,
    WPPWpMailSmtp,
    WPPMc4wp,
    WPPSpectra,
    SquirrelMail,
    PhoneSystem3CX,
    Prestashop,
    Jira,
    Twisted,
    TwistedWeb,
    Symfony,
    TinyMCE,
    JQueryUI,
    WPPLayerSlider,
    WPPWpMembers,
    WPPForminator,
    Horde,
    Knockout,
    WPPWpSuperCache,
    WPPEmailSubscribers,
    WPPBetterSearchReplace,
    WPPAdvancedCustomFields,
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
            _ => vec![ScanType::Http],
        }
    }

    /// Returns the CPE vendor and product as a tuple.
    pub fn get_cpe_vendor_product(&self) -> (String, String) {
        match self {
            Self::Dovecot => ("dovecot".to_string(), "dovecot".to_string()),
            Self::Exim => ("exim".to_string(), "exim".to_string()),
            Self::MariaDB => ("mariadb".to_string(), "mariadb".to_string()),
            Self::MySQL => ("oracle".to_string(), "mysql_server".to_string()),
            Self::OpenSSH => ("openbsd".to_string(), "openssh".to_string()),
            Self::ProFTPD => ("proftpd_project".to_string(), "proftpd".to_string()),
            Self::PureFTPd => ("pureftpd".to_string(), "pure-ftpd".to_string()),
            Self::OS => ("".to_string(), "".to_string()),
            Self::Ubuntu => ("canonical".to_string(), "ubuntu_linux".to_string()),
            Self::Debian => ("debian".to_string(), "debian_linux".to_string()),
            Self::Fedora => ("fedoraproject".to_string(), "fedora".to_string()),
            Self::CentOS => ("centos".to_string(), "centos".to_string()),
            Self::AlmaLinux => ("alma".to_string(), "linux".to_string()),
            Self::OracleLinux => ("oracle".to_string(), "linux".to_string()),
            Self::FreeBSD => ("freebsd".to_string(), "freebsd".to_string()),
            Self::OpenBSD => ("openbsd".to_string(), "openbsd".to_string()),
            Self::NetBSD => ("netbsd".to_string(), "netbsd".to_string()),
            Self::Unix => ("unix".to_string(), "unix".to_string()),
            Self::PHP => ("php".to_string(), "php".to_string()),
            Self::PhpMyAdmin => ("phpmyadmin".to_string(), "phpmyadmin".to_string()),
            Self::Typo3 => ("typo3".to_string(), "typo3".to_string()),
            Self::WordPress => ("wordpress".to_string(), "wordpress".to_string()),
            Self::Drupal => ("drupal".to_string(), "drupal".to_string()),
            Self::Httpd => ("apache".to_string(), "httpd_server".to_string()),
            Self::Tomcat => ("apache".to_string(), "tomcat".to_string()),
            Self::Nginx => ("nginx".to_string(), "nginx".to_string()),
            Self::OpenSSL => ("openssl".to_string(), "openssl".to_string()),
            Self::JQuery => ("jquery".to_string(), "jquery".to_string()),
            Self::ReactJS => ("facebook".to_string(), "react".to_string()),
            Self::Handlebars => ("handlebarsjs".to_string(), "handlebars".to_string()),
            Self::Lodash => ("lodash".to_string(), "lodash".to_string()),
            Self::AngularJS => ("angularjs".to_string(), "angular".to_string()),
            Self::Gsap => (
                "greensock".to_string(),
                "greensock_animation_platform".to_string(),
            ),
            Self::Bootstrap => ("getbootstrap".to_string(), "bootstrap".to_string()),
            Self::Angular => ("angular".to_string(), "angular".to_string()),
            Self::Plesk => ("plesk".to_string(), "plesk".to_string()),
            Self::CKEditor => ("ckeditor".to_string(), "ckeditor".to_string()),
            Self::Highcharts => ("highcharts".to_string(), "highcharts".to_string()),
            Self::WPPYoastSEO => ("yoast".to_string(), "yoastseo".to_string()),
            Self::WPPRevSlider => ("themepunch".to_string(), "slider_revolution".to_string()),
            Self::WPPJSComposer => ("wpbakery".to_string(), "page_builder".to_string()),
            Self::WPPContactForm => ("rocklobster".to_string(), "contact_form_7".to_string()),
            Self::Melis => ("melistechnology".to_string(), "meliscms".to_string()),
            Self::WPPElementor => (
                "webtechstreet".to_string(),
                "elementor_addon_elements".to_string(),
            ),
            Self::WPPElementsReadyLite => ("".to_string(), "".to_string()),
            Self::WPPGTranslate => (
                "gtranslate".to_string(),
                "translate_wordpress_with_gtranslate".to_string(),
            ),
            Self::WPPWooCommerce => ("woocommerce".to_string(), "woocommerce".to_string()),
            Self::WPTDivi => ("elegant_themes".to_string(), "divi".to_string()),
            Self::WPPClassicEditor => ("".to_string(), "".to_string()),
            Self::WPPAkismet => ("automattic".to_string(), "akismet".to_string()),
            Self::WPPWpformsLite => ("wpforms".to_string(), "wpforms".to_string()),
            Self::WPPAllInOneWpMigration => (
                "servmask".to_string(),
                "all-in-one_wp_migration".to_string(),
            ),
            Self::WPPReallySimpleSSL => (
                "really-simple-plugins".to_string(),
                "really-simple-ssl".to_string(),
            ),
            Self::WPPJetpack => ("automattic".to_string(), "jetpack".to_string()),
            Self::WPPLiteSpeedCache => ("litespeedtech".to_string(), "litespeed_cache".to_string()),
            Self::WPPAllInOneSEO => ("aioseo".to_string(), "all_in_one_seo".to_string()),
            Self::WPPWordfence => ("".to_string(), "".to_string()),
            Self::WPPWpMailSmtp => ("wpforms".to_string(), "wp_mail_smtp".to_string()),
            Self::WPPMc4wp => (
                "mailchimp_for_wordpress_project".to_string(),
                "mailchimp_for_wordpress".to_string(),
            ),
            Self::WPPSpectra => ("brainstormforce".to_string(), "spectra".to_string()),
            Self::SquirrelMail => ("squirrelmail".to_string(), "squirrelmail".to_string()),
            Self::PhoneSystem3CX => ("3cx".to_string(), "3cx".to_string()),
            Self::Prestashop => ("prestashop".to_string(), "prestashop".to_string()),
            Self::Jira => ("atlassian".to_string(), "jira".to_string()),
            Self::Twisted => ("twistedmatrix".to_string(), "twisted".to_string()),
            Self::TwistedWeb => ("twistedmatrix".to_string(), "twistedweb".to_string()),
            Self::Symfony => ("sensiolabs".to_string(), "symfony".to_string()),
            Self::TinyMCE => ("tiny".to_string(), "tinymce".to_string()),
            Self::JQueryUI => ("jquery".to_string(), "jquery_ui".to_string()),
            Self::WPPLayerSlider => ("layslider".to_string(), "layslider".to_string()),
            Self::WPPWpMembers => ("wp-members_project".to_string(), "wp-members".to_string()),
            Self::WPPForminator => ("incsub".to_string(), "forminator".to_string()),
            Self::Horde => ("horde".to_string(), "groupware".to_string()),
            Self::Knockout => ("knockoutjs".to_string(), "knockout".to_string()),
            Self::WPPWpSuperCache => ("automattic".to_string(), "wp_super_cache".to_string()),
            Self::WPPEmailSubscribers => ("icegram".to_string(), "email_subscribers".to_string()),
            Self::WPPBetterSearchReplace => {
                ("wpengine".to_string(), "better_search_replace".to_string())
            }
            Self::WPPAdvancedCustomFields => (
                "advancedcustomfields".to_string(),
                "advanced_custom_fields".to_string(),
            ),
        }
    }

    /// Checks whether the technology supports the given scan type
    ///
    /// # Examples
    ///
    /// ```rust
    /// let technology = sanca_software::models::technology::Technology::OpenSSH;
    /// assert!(technology.supports_scan(sanca_software::models::ScanType::Tcp));
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
                    UrlRequest::from_path(main_url, "_profiler/phpinfo", false),
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
                    UrlRequest::from_path(main_url, "/phpmyadmin/ChangeLog", false),
                    UrlRequest::from_path(main_url, "/phpMyAdmin/ChangeLog", false),
                    UrlRequest::from_path(main_url, "/phpMyAdmin/doc/html/index.html", false),
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
                    UrlRequest::from_path(main_url, "wp-admin/install.php", false),
                    UrlRequest::from_path(main_url, "wp-login.php", false),
                ]
            }
            Self::Plesk => {
                vec![UrlRequest::from_path(main_url, "/login_up.php", false)]
            }
            Self::WPPYoastSEO => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wordpress-seo/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wordpress-seo/readme.txt",
                        false,
                    ),
                ]
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
            Self::WPPElementor => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/elementor/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/elementor/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPElementsReadyLite => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/element-ready-lite/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/element-ready-lite/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPGTranslate => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/gtranslate/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/gtranslate/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPClassicEditor => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/classic-editor/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/classic-editor/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPAkismet => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/akismet/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(main_url, "wp-content/plugins/akismet/readme.txt", false),
                ]
            }
            Self::WPPWpformsLite => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wpforms-lite/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wpforms-lite/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPAllInOneWpMigration => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/all-in-one-wp-migration/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/all-in-one-wp-migration/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPReallySimpleSSL => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/really-simple-ssl/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/really-simple-ssl/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPJetpack => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/jetpack/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(main_url, "wp-content/plugins/jetpack/readme.txt", false),
                ]
            }
            Self::WPPLiteSpeedCache => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/litespeed-cache/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/litespeed-cache/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPAllInOneSEO => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/all-in-one-seo-pack/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/all-in-one-seo-pack/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPWordfence => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wordfence/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wordfence/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPWpMailSmtp => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wp-mail-smtp/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wp-mail-smtp/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPMc4wp => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/mailchimp-for-wp/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/mailchimp-for-wp/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPSpectra => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPTDivi => {
                vec![
                    UrlRequest::from_path(main_url, "/wp-content/themes/Divi/style.css", false),
                    UrlRequest::from_path(main_url, "wp-content/themes/Divi/style.css", false),
                ]
            }
            Self::Melis => {
                vec![UrlRequest::from_path(main_url, "/melis/login", false)]
            }
            Self::SquirrelMail => {
                vec![
                    UrlRequest::from_path(main_url, "src/login.php", false),
                    UrlRequest::from_path(main_url, "/squirrelmail/src/login.php", false),
                ]
            }
            Self::PhoneSystem3CX => {
                vec![UrlRequest::from_path(main_url, "/webclient/", true)]
            }
            Self::Prestashop => {
                vec![UrlRequest::from_path(
                    main_url,
                    "/docs/CHANGELOG.txt",
                    false,
                )]
            }
            Self::Symfony => {
                vec![
                    UrlRequest::new(main_url, false),
                    UrlRequest::from_path(main_url, "/app_dev.php", false),
                ]
            }
            Self::WPPLayerSlider => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/LayerSlider/static/layerslider/js/layerslider.kreaturamedia.jquery.js",
                        false,
                    ),
                    UrlRequest::from_path(
			main_url,
			"wp-content/plugins/LayerSlider/static/layerslider/js/layerslider.kreaturamedia.jquery.js",
			false,
		    ),
		    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/LayerSlider/static/js/layerslider.kreaturamedia.jquery.js",
                        false,
                    ),
                    UrlRequest::from_path(
			main_url,
			"wp-content/plugins/LayerSlider/static/js/layerslider.kreaturamedia.jquery.js",
			false,
		    ),
                ]
            }
            Self::WPPWpMembers => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wp-members/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wp-members/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPForminator => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/forminator/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/forminator/readme.txt",
                        false,
                    ),
                ]
            }
            Self::Horde => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/horde/services/help/index.php?module=horde&show=menu",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "horde/services/help/index.php?module=horde&show=menu",
                        false,
                    ),
                ]
            }
            Self::WPPWpSuperCache => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/wp-super-cache/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/wp-super-cache/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPEmailSubscribers => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/email-subscribers/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/email-subscribers/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPBetterSearchReplace => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/better-search-replace/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/better-search-replace/readme.txt",
                        false,
                    ),
                ]
            }
            Self::WPPAdvancedCustomFields => {
                vec![
                    UrlRequest::from_path(
                        main_url,
                        "/wp-content/plugins/advanced-custom-fields/readme.txt",
                        false,
                    ),
                    UrlRequest::from_path(
                        main_url,
                        "wp-content/plugins/advanced-custom-fields/readme.txt",
                        false,
                    ),
                ]
            }
            _ => vec![UrlRequest::new(main_url, true)],
        }
    }
}

impl Display for Technology {
    /// Format a Technology
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
	let s = match self {
            Technology::Dovecot => "Dovecot".to_string(),
            Technology::Exim => "Exim".to_string(),
            Technology::MariaDB => "MariaDB".to_string(),
            Technology::MySQL => "MySQL".to_string(),
            Technology::OpenSSH => "OpenSSH".to_string(),
            Technology::ProFTPD => "ProFTPD".to_string(),
            Technology::PureFTPd => "PureFTPd".to_string(),
            Technology::OS => "OS".to_string(),
            Technology::Ubuntu => "Ubuntu".to_string(),
            Technology::Debian => "Debian".to_string(),
            Technology::CentOS => "CentOS".to_string(),
            Technology::Fedora => "Fedora".to_string(),
            Technology::AlmaLinux => "AlmaLinux".to_string(),
            Technology::OracleLinux => "OracleLinux".to_string(),
            Technology::FreeBSD => "FreeBSD".to_string(),
            Technology::OpenBSD => "OpenBSD".to_string(),
            Technology::NetBSD => "NetBSD".to_string(),
            Technology::Unix => "Unix".to_string(),
            Technology::PHP => "PHP".to_string(),
            Technology::PhpMyAdmin => "phpMyAdmin".to_string(),
            Technology::Typo3 => "TYPO3".to_string(),
            Technology::WordPress => "WordPress".to_string(),
            Technology::Drupal => "Drupal".to_string(),
            Technology::Httpd => "Apachehttpd".to_string(),
            Technology::Tomcat => "Tomcat".to_string(),
            Technology::Nginx => "Nginx".to_string(),
            Technology::OpenSSL => "OpenSSL".to_string(),
            Technology::JQuery => "jQuery".to_string(),
            Technology::ReactJS => "React".to_string(),
            Technology::Handlebars => "Handlebars".to_string(),
            Technology::Lodash => "Lodash".to_string(),
            Technology::AngularJS => "AngularJS".to_string(),
            Technology::Gsap => "GSAP".to_string(),
            Technology::Bootstrap => "Bootstrap".to_string(),
            Technology::Angular => "Angular".to_string(),
            Technology::Plesk => "Plesk".to_string(),
            Technology::CKEditor => "CKEditor".to_string(),
            Technology::Highcharts => "Highcharts".to_string(),
            Technology::WPPYoastSEO => "YoastSEO".to_string(),
            Technology::WPPRevSlider => "SliderRevolution".to_string(),
            Technology::WPPJSComposer => "JSComposer".to_string(),
            Technology::WPPContactForm => "ContactForm7".to_string(),
            Technology::Melis => "Melis".to_string(),
            Technology::WPPElementor => "Elementor".to_string(),
            Technology::WPPElementsReadyLite => "ElementsReadyLite".to_string(),
            Technology::WPPGTranslate => "GTranslate".to_string(),
            Technology::WPPWooCommerce => "WooCommerce".to_string(),
            Technology::WPTDivi => "Divi".to_string(),
            Technology::WPPClassicEditor => "ClassicEditor".to_string(),
            Technology::WPPAkismet => "Akismet".to_string(),
            Technology::WPPWpformsLite => "WpFormsLite".to_string(),
            Technology::WPPAllInOneWpMigration => "AllInOneWpMigration".to_string(),
            Technology::WPPReallySimpleSSL => "ReallySimpleSSL".to_string(),
            Technology::WPPJetpack => "Jetpack".to_string(),
            Technology::WPPLiteSpeedCache => "LiteSpeedCache".to_string(),
            Technology::WPPAllInOneSEO => "AllInOneSEO".to_string(),
            Technology::WPPWordfence => "Wordfence".to_string(),
            Technology::WPPWpMailSmtp => "WpMailSmtp".to_string(),
            Technology::WPPMc4wp => "Mc4wp".to_string(),
            Technology::WPPSpectra => "Spectra".to_string(),
            Technology::SquirrelMail => "SquirrelMail".to_string(),
            Technology::PhoneSystem3CX => "PhoneSystem3CX".to_string(),
            Technology::Prestashop => "Prestashop".to_string(),
            Technology::Jira => "Jira".to_string(),
            Technology::Twisted => "Twisted".to_string(),
            Technology::TwistedWeb => "TwistedWeb".to_string(),
            Technology::Symfony => "Symfony".to_string(),
            Technology::TinyMCE => "TinyMCE".to_string(),
            Technology::JQueryUI => "jQueryUI".to_string(),
            Technology::WPPLayerSlider => "LayerSlider".to_string(),
            Technology::WPPWpMembers => "WpMembers".to_string(),
            Technology::WPPForminator => "Forminator".to_string(),
            Technology::Horde => "Horde".to_string(),
            Technology::Knockout => "Knockout".to_string(),
            Technology::WPPWpSuperCache => "WpSuperCache".to_string(),
            Technology::WPPEmailSubscribers => "EmailSubscribers".to_string(),
            Technology::WPPBetterSearchReplace => "BetterSearchReplace".to_string(),
            Technology::WPPAdvancedCustomFields => "AdvancedCustomFields".to_string(),
        };
	write!(f, "{}", s)
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
            Technology::WPPElementor,
            Technology::WPPElementsReadyLite,
            Technology::WPPGTranslate,
            Technology::WPPWooCommerce,
            Technology::WPTDivi,
            Technology::WPPClassicEditor,
            Technology::WPPAkismet,
            Technology::WPPWpformsLite,
            Technology::WPPAllInOneWpMigration,
            Technology::WPPReallySimpleSSL,
            Technology::WPPJetpack,
            Technology::WPPLiteSpeedCache,
            Technology::WPPAllInOneSEO,
            Technology::WPPWordfence,
            Technology::WPPWpMailSmtp,
            Technology::WPPMc4wp,
            Technology::WPPSpectra,
            Technology::SquirrelMail,
            Technology::PhoneSystem3CX,
            Technology::Prestashop,
            Technology::Jira,
            Technology::Twisted,
            Technology::TwistedWeb,
            Technology::Symfony,
            Technology::TinyMCE,
            Technology::JQueryUI,
            Technology::WPPLayerSlider,
            Technology::WPPWpMembers,
            Technology::WPPForminator,
            Technology::Horde,
            Technology::Knockout,
            Technology::WPPWpSuperCache,
            Technology::WPPEmailSubscribers,
            Technology::WPPBetterSearchReplace,
            Technology::WPPAdvancedCustomFields,
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
            Technology::WPPElementor => Some(PossibleValue::new("elementor")),
            Technology::WPPElementsReadyLite => Some(PossibleValue::new("elementreadylite")),
            Technology::WPPGTranslate => Some(PossibleValue::new("gtranslate")),
            Technology::WPPWooCommerce => Some(PossibleValue::new("woocommerce")),
            Technology::WPTDivi => Some(PossibleValue::new("divi")),
            Technology::WPPClassicEditor => Some(PossibleValue::new("classiceditor")),
            Technology::WPPAkismet => Some(PossibleValue::new("akismet")),
            Technology::WPPWpformsLite => Some(PossibleValue::new("wpformslite")),
            Technology::WPPAllInOneWpMigration => Some(PossibleValue::new("allinonewpmigration")),
            Technology::WPPReallySimpleSSL => Some(PossibleValue::new("reallysimplessl")),
            Technology::WPPJetpack => Some(PossibleValue::new("jetpack")),
            Technology::WPPLiteSpeedCache => Some(PossibleValue::new("litespeedcache")),
            Technology::WPPAllInOneSEO => Some(PossibleValue::new("allinoneseo")),
            Technology::WPPWordfence => Some(PossibleValue::new("wordfence")),
            Technology::WPPWpMailSmtp => Some(PossibleValue::new("wpmailsmtp")),
            Technology::WPPMc4wp => Some(PossibleValue::new("mc4wp")),
            Technology::WPPSpectra => Some(PossibleValue::new("spectra")),
            Technology::SquirrelMail => Some(PossibleValue::new("squirrelmail")),
            Technology::PhoneSystem3CX => Some(PossibleValue::new("phonesystem3cx")),
            Technology::Prestashop => Some(PossibleValue::new("prestashop")),
            Technology::Jira => Some(PossibleValue::new("jira")),
            Technology::Twisted => Some(PossibleValue::new("twisted")),
            Technology::TwistedWeb => Some(PossibleValue::new("twistedweb")),
            Technology::Symfony => Some(PossibleValue::new("symfony")),
            Technology::TinyMCE => Some(PossibleValue::new("tinymce")),
            Technology::JQueryUI => Some(PossibleValue::new("jqueryui")),
            Technology::WPPLayerSlider => Some(PossibleValue::new("layerslider")),
            Technology::WPPWpMembers => Some(PossibleValue::new("wpmembers")),
            Technology::WPPForminator => Some(PossibleValue::new("forminator")),
            Technology::Horde => Some(PossibleValue::new("horde")),
            Technology::Knockout => Some(PossibleValue::new("knockout")),
            Technology::WPPWpSuperCache => Some(PossibleValue::new("wpsupercache")),
            Technology::WPPEmailSubscribers => Some(PossibleValue::new("emailsubscribers")),
            Technology::WPPBetterSearchReplace => Some(PossibleValue::new("bettersearchreplace")),
            Technology::WPPAdvancedCustomFields => Some(PossibleValue::new("advancedcustomfields")),
            // Ignore the specific OS since they cannot be given as CLI argument. Use OS instead.
            _ => None,
        }
    }
}
