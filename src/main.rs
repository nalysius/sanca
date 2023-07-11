use sanca::application::Application;

use std::env;

fn main() {
    let application = Application::new();
    let args: Vec<String> = env::args().collect();

    // ip_hostname and port parameters are mandatory
    if args.len() < 3 {
        application.show_usage();
    } else {
        let ip_hostname = args.get(1).unwrap();
        let port_arg = args.get(2).unwrap().parse::<u16>();
        if let Ok(port) = port_arg {
            application.run(ip_hostname, port);
        } else {
            println!("Please enter a valid port");
            application.show_usage();
        }
    }
}
