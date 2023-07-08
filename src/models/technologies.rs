//! This module declares the technologies

use super::Port;

/// It's broad, it could be a programming language, a software or even a
/// JavaScript library
pub struct Technology {
    /// The name of the technology
    /// Example: OpenSSH
    pub name: String,
    /// The default ports the technology is known to run on
    /// Example: OpenSSH -> 22/tcp
    pub default_ports: Vec<Port>,
    /// The list of regex used to match the technology
    pub regex: Vec<String>,
}

impl Technology {
    /// Creates a new technology
    pub fn new(name: &str, default_ports: &[Port], regex: &[&str]) -> Self {
        Technology {
            name: name.to_string(),
            default_ports: default_ports.to_vec(),
            regex: regex.iter()
                    .map(|x| x.to_string())
                    .collect(),
        }
    }

    /// Checks whether a technology is known to run on a given port
    pub fn runs_on(&self, port: Port) -> bool {
        // Check if the given port is in the default ports of the technology
        for default_port in &self.default_ports {
            if default_port == &port {
                return true;
            }
        }
        false
    }
}

/// Get the list of all supported technologies
pub fn get_technologies_list() -> Vec<Technology> {
    let openssh_ports = [Port::new_tcp(22)];
    // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
    let openssh_regex = r"/^SSH-\d.\d-OpenSSH_(\d+\.\d+([a-z]\d)?) [a-zA-Z0-9]+(-\d)?/";
    vec![
        Technology::new("OpenSSH", &openssh_ports, &[openssh_regex]),
    ]
}