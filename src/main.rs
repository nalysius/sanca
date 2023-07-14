use sanca::application::Application;

fn main() {
    let mut application = Application::new();
    application.read_argv();
    application.run();
}
