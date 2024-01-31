use std::process::Command;

pub(crate) fn devices() -> Vec<String> {
    // TODO: https://github.com/imkira/mobiledevice

    let output = String::from_utf8(
        Command::new("ios-deploy")
            .arg("-c")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let mut devices = Vec::new();

    for line in output.lines() {
        const PREFIX: &str = "[....] Found ";

        if line.starts_with(PREFIX) {
            devices.push(
                line.trim_start_matches(PREFIX)
                    .split_once(' ')
                    .unwrap()
                    .0
                    .to_owned(),
            );
        }
    }

    devices
}
