use log::debug;
use sanca_software::application::Application;

fn main() {
    //simple_logger::init_with_level(log::Level::Info).unwrap();
    debug!("Starting application");
    let show_header = true;
    let mut application = Application::new(show_header);
    application.read_argv();
    application.run();
}
