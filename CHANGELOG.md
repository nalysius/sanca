# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- WordPress detection.
- Tomcat detection.
- AngularJS detection.
- GSAP detection.
- TYPO3 detection.
- phpMyAdmin detection.
- A CSV writer to get the findings in CSV.

### Fixed

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
