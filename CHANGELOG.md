# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Highcharts detection.
- Support for gzip-encoded response body.

### Changed

- A technology can be identified more than once. Useful for JavaScript
  library installed several times on a same website.

### Fixed

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
