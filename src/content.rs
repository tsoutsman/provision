use std::time::SystemTime;

use base64::Engine;
use cms::{
    cert::x509::{
        der::{asn1::OctetString, Any, Encode},
        spki::ObjectIdentifier,
        Certificate,
    },
    signed_data::EncapsulatedContentInfo,
};
use der::DateTime;

use crate::{certificate::developer_certificate, device::devices};

const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

pub(crate) fn encapsulated_content_info() -> EncapsulatedContentInfo {
    let profile = Profile {
        bundle_identifier: vec!["com".to_owned(), "dummy".to_owned(), "abcdefg".to_owned()],
        application_identifier_prefix: "4H97C7924V".to_owned(),
        creation_date: DateTime::from_system_time(SystemTime::now())
            .expect("couldn't convert current time"),
        developer_certificate: developer_certificate(None),
        team_name: "Klimenty Tsoutsman".to_owned(),
    };
    println!("{}", xml(&profile));
    let content = OctetString::new(xml(&profile)).unwrap();

    EncapsulatedContentInfo {
        econtent_type: SHA1_OID,
        econtent: Some(Any::encode_from(&content).unwrap()),
    }
}

struct Profile {
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
}

fn xml(profile: &Profile) -> String {
    // TODO: IsXcodeManaged?
    // TODO: get-task-allow
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>{app_id_name}</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>{application_identifier_prefix}</string>
	</array>
	<key>CreationDate</key>
	<date>{creation_date}</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
		<string>xrOS</string>
		<string>visionOS</string>
	</array>
	<key>IsXcodeManaged</key>
	<true/>
	<key>DeveloperCertificates</key>
	<array>
	    <data>{developer_certificate}</data>
	</array>

	<key>DER-Encoded-Profile</key>
	<data>{der_encoded_profile}</data>
    
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key>
		<string>{application_identifier}</string>

        <key>keychain-access-groups</key>
		<array>
				<string>{keychain_access_groups}</string>
		</array>

        <key>get-task-allow</key>
		<true/>

        <key>com.apple.developer.team-identifier</key>
        <string>{team_identifier}</string>
	</dict>
	
	<key>ExpirationDate</key>
	<date>2024-02-04T23:51:24Z</date>
	
	<key>Name</key>
	<string>{name}</string>
	
	<key>ProvisionedDevices</key>
	<array>
	    {provisioned_devices}
	</array>
	
	<key>LocalProvision</key>
	<true/>
	
	<key>TeamIdentifier</key>
	<array>
		<string>{team_identifier}</string>
	</array>
	
	<key>TeamName</key>
	<string>{team_name}</string>
	
	<key>TimeToLive</key>
	<integer>7</integer>
	
	<key>UUID</key>
	<string>{uuid}</string>
	
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>"#,
        app_id_name = profile.app_id_name(),
        application_identifier_prefix = profile.application_identifier_prefix,
        creation_date = profile.creation_date,
        developer_certificate = base64::prelude::BASE64_STANDARD
            .encode(profile.developer_certificate.to_der().unwrap()),
        application_identifier = profile.application_identifier(),
        keychain_access_groups = profile.keychain_access_groups(),
        provisioned_devices = devices()
            .iter()
            .map(|device_id| format!("<string>{device_id}</string>"))
            .collect::<Vec<_>>()
            .join("\n        "),
        team_identifier = profile.application_identifier_prefix,
        team_name = profile.team_name,
        uuid = "",
        name = profile.name(),
        der_encoded_profile = der(profile),
    )
}

fn der(_profile: &Profile) -> String {
    "".to_owned()
}
