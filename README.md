# Sanca

Using regex, Sanca tries to recognize software based on their banner or the
data they transmit (e.g. HTTP responses). Moreover, it provides an evidence
for each finding.

## Usage

```
$ ./sanca --help
A scanner to discover what technologies are running on a remote host. Focus on providing evidences.

Usage: sanca [OPTIONS] --scan-type <SCAN_TYPE>

Options:
  -u, --url <URL>                    The URL where to send an HTTP request
  -i, --ip-hostname <IP_HOSTNAME>    The IP or hostname to connect on
  -p, --port <PORT>                  The port to connect on
  -s, --scan-type <SCAN_TYPE>        The type of scan [possible values: tcp, http, udp]
  -t, --technologies <TECHNOLOGIES>  [possible values: dovecot, exim, mariadb, mysql, openssh, proftpd, pureftpd, os, js, PHP, phpmyadmin, wordpress, drupal, typo3]
  -h, --help                         Print help
  -V, --version                      Print version
```

## Examples

### TCP / UDP scans

```
./sanca -s tcp -p 22 -i example.org
./sanca -s udp -p 53 -i example.org
```

The examples above perform a scan of port 22/tcp and 53/udp respectively, on host example.org.

> Note: UDP scan is not implemented yet.

### HTTP scan

```
./sanca -s http -u https://example.com/phpmyadmin
./sanca -s http -t wordpress -u https://example.com/blog/index.php
```

The above example performs one HTTP scan at the URL `https://example.com/phpmyadmin`,
and another at `https://example.com/blog/index.php`, where only WordPress will be
checked.

