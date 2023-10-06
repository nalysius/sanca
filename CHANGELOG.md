# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Detection of WordPress plugin Yoast SEO.
- Detection of WordPress plugin RevSlider (Slider Revolution).
- Detection of WordPress plugin js_composer.
- Detection of OS (Debian only) & OS version from MariaDB banner.
- Detection of Ubuntu 23.10 (Mantic) from Apache httpd.
- New regex for not minified Lodash JS.
- New regex for minified Highcharts JS.

### Changed

- Improve OS version detection from OpenSSH by using the deb / bpo part of the banner.

### Fixed

- The wrong OS version was detected when OpenSSH was installed from
  backports.

## [0.5.0]

### Added

- Two more regexes for a better detection of Lodash.
- -a|--user-agent option to use a custom user-agent.
- One more regex for a better detection of Handlebars.
- One more regex to detect Highcharts from the comment at the top of
  the file.

### Fixed

- OSChecker panicked when OpenSSH was detected without OS in banner.
- Variants of comment header for jQuery and Handlebars weren't detected.
- The right MIME type is given when sending HTTP request to fetch JavaScript files.
- Findings are deduplicated. A technology / version pair is reported only once,
  even if detected in several files.
- When a HTTP header was present several times, only the last value was kept. It
  was possible to lost a value (typically x-powered-by).
- WordPress wasn't detected in the <meta HTML tag if its version was only X.Y and
  not X.Y.Z.

## [0.4.0]

### Added

- Highcharts detection.
- Support for gzip-encoded response body.
- Detection for Debian 7 when Apache 2.2.22 is used.

### Changed

- A technology can be identified more than once. Useful for JavaScript
  library installed several times on a same website.
- The HTTP status code is now available to all HttpCheckers. WordPress
  use it to reduce false positive.
- Path /phpmyadmin/ is fetched for PHPChecker, since phpMyAdmin sometimes
  reveals the PHP version.

### Fixed

- jQuery wasn't detected if one part of the version had more than one digit.
- Sanca panicked when Nginx was encountered without the OS in the header.

## [0.3.0]

### Added

- CKEditor detection.
- Unit tests.
- Plesk detection.
- Angular detection.
- ReactJS detection.

### Fixed

- Bootstrap was wrongly identified when another library used a variable containing "VERSION".
- When fetching JavaScript files, the images were downloaded too.
- When fetching JavaScript files, the URLs starting with // were ignored: //www.example.com/a/b.js.

## [0.2.0]

### Added

- Bootstrap detection.
- WordPress detection.
- Tomcat detection.
- AngularJS detection.
- GSAP detection.
- TYPO3 detection.
- phpMyAdmin detection.
- A CSV writer to get the findings in CSV.

### Fixed

- JavaScript files whose URL path contained a '@' weren't downloaded.
- Some technologies (e.g. PHP) were identified from other servers with
  JavaScript files.
- The Nginx version wasn't extracted from HTTP headers.
- In the evidence text when Apache httpd was identified using its signature, the
  variables like evidence and url of finding were not replaced by their values.
- OpenSSH detection crashed the program.
- Evidences found in HTTP headers are truncated in the same way. The 45 first and
  45 last chars are conserved. Affects checkers OpenSSL, PHP, Nginx, Apache httpd,
  and OS.

### Changed

- OS detection determines the OS version based on the software version.

## [0.1.0]

### Added

- OpenSSH detection
- Dovecot detection
- Exim detection
- MySQL detection
- MariaDB detection
- OS detection
- ProFTPD detection
- PureDTPd detection
- Apache httpd detection
- Nginx detection
- PHP detection
- OpenSSL detection
- jQuery detection
- Handlebars detection
- Lodash detection
