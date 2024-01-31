use std::process::Command;

use base64::Engine;
use cms::cert::x509::{der::Decode, Certificate};

pub(crate) fn developer_certificate(email: Option<String>) -> Certificate {
    // TODO: Suport searching for specific certificate hash e.g. if system has two
    // development certificates with same email.
    let certificate_name = if let Some(email) = email {
        format!("Apple Development: {email}")
    } else {
        "Apple Development:".to_owned()
    };

    let output = Command::new("security")
        .args(["find-certificate", "-p", "-c", &certificate_name])
        .output()
        .unwrap();
    let certificate_string = String::from_utf8(output.stdout).unwrap();

    parse_certificate(certificate_string)
}

pub(crate) fn provisioning_certificate() -> Certificate {
    let output = Command::new("security")
        .args([
            "find-certificate",
            "-p",
            "-c",
            "Apple iPhone OS Provisioning Profile Signing",
        ])
        .output()
        .unwrap();
    let certificate_string = String::from_utf8(output.stdout).unwrap();

    parse_certificate(certificate_string)
}

fn parse_certificate(string: String) -> Certificate {
    let string = string
        .trim_start_matches("-----BEGIN CERTIFICATE-----\n")
        .trim_end_matches("\n-----END CERTIFICATE-----\n")
        .replace('\n', "");
    let base64 = base64::prelude::BASE64_STANDARD.decode(string).unwrap();
    Certificate::from_der(&base64).unwrap()
}
