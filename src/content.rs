mod der;
mod xml;

use std::time::{Duration, SystemTime};

use ::der::DateTime;
use cms::{
    cert::x509::{
        der::{asn1::OctetString, Any},
        spki::ObjectIdentifier,
        Certificate,
    },
    signed_data::EncapsulatedContentInfo,
};
use der::der;
use uuid::Uuid;
use xml::xml;

use crate::certificate::developer_certificate;

const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

const DAYS_TO_EXPIRY: u64 = 7;

pub(crate) fn encapsulated_content_info() -> EncapsulatedContentInfo {
    let profile = Profile {
        uuid: "7e71d281-cdf0-45f8-9851-403d8d619756".parse().unwrap(),
        bundle_identifier: vec![
            "com".to_owned(),
            "dummy".to_owned(),
            "uauaoeuaeoUITests".to_owned(),
        ],
        application_identifier_prefix: "4H97C7924V".to_owned(),
        creation_date: DateTime::from_system_time(SystemTime::now())
            .expect("couldn't convert current time"),
        developer_certificate: developer_certificate(None),
        team_name: "Klimenty Tsoutsman".to_owned(),
    };
    let content = OctetString::new(xml(&profile)).unwrap();

    EncapsulatedContentInfo {
        econtent_type: SHA1_OID,
        econtent: Some(Any::encode_from(&content).unwrap()),
    }
}

struct Profile {
    uuid: Uuid,
    bundle_identifier: Vec<String>,
    application_identifier_prefix: String,
    creation_date: DateTime,
    developer_certificate: Certificate,
    team_name: String,
    // TODO: Custom platforms?
}

impl Profile {
    fn name(&self) -> String {
        format!(
            "iOS Team Provisioning Profile: {}",
            self.bundle_identifier.join(".")
        )
    }

    fn app_id_name(&self) -> String {
        format!("XC {}", self.bundle_identifier.join(" "))
    }

    fn application_identifier(&self) -> String {
        format!(
            "{}.{}",
            self.application_identifier_prefix,
            self.bundle_identifier.join(".")
        )
    }

    fn keychain_access_groups(&self) -> String {
        format!("{}.*", self.application_identifier_prefix)
    }

    fn expiration_date(&self) -> DateTime {
        DateTime::from_unix_duration(
            self.creation_date.unix_duration() + Duration::from_secs(DAYS_TO_EXPIRY * 24 * 60 * 60),
        )
        .unwrap()
    }
}
