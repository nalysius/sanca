//! This module declares a TCP reader. The objective is to easily read
//! data over TCP.

use log::{debug, warn};
use log::{error, trace};

use std::io::prelude::*;
use std::io::Result as IoResult;
use std::net::TcpStream;
use std::time::Duration;

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
        trace!("Running TcpReader::read()");
        trace!("Want to read {} bytes", bytes_to_read);
        let mut stream = TcpStream::connect(format!("{}:{}", self.ip_hostname, self.port))?;
        let timeout = Duration::new(1, 0);
        stream.set_read_timeout(Some(timeout))?;
        // Store bytes in data, buffer is only temporary
        let mut data: Vec<u8> = Vec::new();

        trace!("Start reading data");
        while data.len() < bytes_to_read {
            let mut buffer: [u8; 128] = [0; 128];
            trace!("Reading...");
            let read_result = stream.read(&mut buffer);
            trace!("Got a read result");

            // If an error occures during reading, it is returned only
            // if no data has been read at all. If at least something was
            // read, stop reading and return what we already have.
            if let Err(e) = read_result {
                warn!("Got an error while reading over TCP: {:?}", e);
                if data.len() == 0 {
                    error!("No data has been read at all");
                    return Err(e);
                } else {
                    debug!("Data have been read, use it and ignore the error");
                    break;
                }
            } else {
                trace!("Store the data read");
                data.append(&mut buffer.to_vec());
            }
        }
        if data.len() > bytes_to_read {
            trace!("Got more data than needed, truncating");
            data.truncate(bytes_to_read);
        }

        let from_utf8 = String::from_utf8_lossy(&data);
        return Ok(from_utf8.to_string());
    }
}
