use base64::Engine;
use cms::cert::x509::der::Encode;

use crate::{
    content::{der, Profile, DAYS_TO_EXPIRY},
    device::devices,
};

pub(super) fn xml(profile: &Profile) -> String {
    // TODO: IsXcodeManaged?
    // TODO: get-task-allow
    // TODO: ExpirationDate
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
    <integer>{DAYS_TO_EXPIRY}</integer>

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
        uuid = profile.uuid,
        name = profile.name(),
        der_encoded_profile = der(profile),
    )
}
