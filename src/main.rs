use log::debug;
use sanca::application::Application;

fn main() {
    //simple_logger::init_with_level(log::Level::Error).unwrap();
    debug!("Starting application");
    let mut application = Application::new();
    application.read_argv();
    application.run();
}
