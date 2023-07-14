//! This module declares a TCP reader. The objective is to easily read
//! data over TCP.

use std::time::Duration;
use std::io::Result as IoResult;
use std::io::prelude::*;
use std::net::TcpStream;

/// A TCP reader
pub struct TcpReader {
    /// The IP address or hostname to connect
    pub ip_hostname: String,
    /// The port for connection
    pub port: u16,
}

impl TcpReader {
    /// Creates a new TcpReader
    pub fn new(ip_hostname: &str, port: u16) -> Self {
        TcpReader {
            ip_hostname: ip_hostname.to_string(),
            port,
        }
    }

    /// Reads the given number of bytes.
    pub fn read(&self, bytes_to_read: usize) -> IoResult<String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.ip_hostname, self.port))?;
        let timeout = Duration::new(1, 0);
        stream.set_read_timeout(Some(timeout))?;
        // Store bytes in data, buffer is only temporary
        let mut data: Vec<u8> = Vec::new();

        while data.len() < bytes_to_read {
            let mut buffer: [u8; 128] = [0; 128];
            let read_result = stream.read(&mut buffer);

            // If an error occures during reading, it is returned only
            // if no data has been read at all. If at least something was
            // read, stop reading and return what we already have.
            if let Err(e) = read_result {
                if data.len() == 0 {
                   return Err(e);
                } else {
                    break;
                }
            } else {
                data.append(&mut buffer.to_vec());
            }
        }
        if data.len() > bytes_to_read {
            data.truncate(bytes_to_read);
        }

        let from_utf8 = String::from_utf8_lossy(&data);
        return Ok(from_utf8.to_string());

    }
}