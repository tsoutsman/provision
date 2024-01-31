use std::fmt::Write;

use base64::Engine;
use der::{
    asn1::{Any, SequenceOf, SetOfVec, Utf8StringRef},
    Encode, EncodeValue, FixedTag, Length, Tag, TagNumber, Writer,
};
use sha2::Digest;

use crate::{
    content::{Profile, DAYS_TO_EXPIRY},
    devices,
};

macro_rules! kv {
    ($key:literal, $value:expr) => {{
        let mut sequence = SequenceOf::<Any, 2>::new();
        sequence
            .add(Any::encode_from(&string($key)).unwrap())
            .unwrap();
        sequence.add(Any::encode_from(&$value).unwrap()).unwrap();
        Any::encode_from(&sequence).unwrap()
    }};
}

// macro_rules! replace_expr {
//     ($_t:tt $sub:expr) => {
//         $sub
//     };
// }
//
// macro_rules! sequence {
//     () => {
//         SequenceOf::<Any, 0>::new();
//     };
//     ($elem:expr; $n:expr) => {
//         $crate::__rust_force_expr!($crate::vec::from_elem($elem, $n))
//     };
//     ($($x:expr),+ $(,)?) => {
//         {
//             const LEN: usize = 0 $(+ replace_expr!($x 1))+;
//
//             let mut sequence = SequenceOf::<Any, LEN>::new();
//             $(sequence.add(Any::encode_from(&$x).unwrap()).unwrap();)+
//             Any::encode_from(&sequence).unwrap()
//         }
//     };
// }

fn string(s: &str) -> Utf8StringRef {
    Utf8StringRef::new(s).unwrap()
}

pub(crate) fn der(profile: &Profile) -> String {
    let mut set = SetOfVec::<Any>::new();

    set.insert(kv!("Version", 1)).unwrap();

    set.insert(kv!("TimeToLive", DAYS_TO_EXPIRY)).unwrap();

    // TODO
    set.insert(kv!("IsXcodeManaged", true)).unwrap();

    set.insert(kv!("LocalProvision", true)).unwrap();

    set.insert(kv!("CreationDate", profile.creation_date))
        .unwrap();

    set.insert(kv!("TeamName", string("Klimenty Tsoutsman")))
        .unwrap();

    set.insert(kv!(
        "TeamIdentifier",
        [string(&profile.application_identifier_prefix)]
    ))
    .unwrap();

    set.insert(kv!("ExpirationDate", profile.expiration_date()))
        .unwrap();

    // TODO: Custom Platforms
    set.insert(kv!(
        "Platform",
        [string("iOS"), string("xrOS"), string("visionOS")]
    ))
    .unwrap();

    set.insert(kv!("ProfileDistributionType", string("LIMITED")))
        .unwrap();

    set.insert(kv!("AppIDName", string(&profile.app_id_name())))
        .unwrap();

    set.insert(kv!(
        "ApplicationIdentifierPrefix",
        [string(&profile.application_identifier_prefix)]
    ))
    .unwrap();

    set.insert(kv!("UUID", string(&profile.uuid.to_string())))
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(cms::cert::x509::der::Encode::to_der(&profile.developer_certificate).unwrap());
    let hash = hasher.finalize();

    let mut s = String::with_capacity(hash.len() * 2);
    for byte in hash {
        write!(s, "{:02X}", byte).unwrap();
    }
    set.insert(kv!("DeveloperCertificates", [string(&s)]))
        .unwrap();

    set.insert(kv!("Name", string(&profile.name()))).unwrap();

    set.insert(kv!("ProvisionedDevices", devices())).unwrap();

    set.insert(kv!("Entitlements", Entitlements { profile }))
        .unwrap();

    base64::prelude::BASE64_STANDARD.encode(set.to_der().unwrap())
}

struct Entitlements<'a> {
    profile: &'a Profile,
}

impl EncodeValue for Entitlements<'_> {
    fn value_len(&self) -> der::Result<Length> {
        Ok(Length::new(186))
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        1.encode(encoder)?;

        let application_identifier = kv!(
            "application-identifier",
            string(&self.profile.application_identifier())
        );
        let team_identifier = kv!(
            "com.apple.developer.team-identifier",
            string(&self.profile.application_identifier_prefix)
        );
        let get_task_allow = kv!("get-task-allow", true);
        let keychain_access_groups = kv!(
            "keychain-access-groups",
            [self.profile.keychain_access_groups()]
        );

        let len = ((((application_identifier.value_len().unwrap()
            + team_identifier.value_len().unwrap())
        .unwrap()
            + get_task_allow.value_len().unwrap())
        .unwrap()
            + keychain_access_groups.value_len().unwrap())
        .unwrap()
            // TODO: Wrong if the length is encoded in more than one byte.
            + Length::new(4 * 2))
        .unwrap();

        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::N16,
        }
        .encode(encoder)?;
        len.encode(encoder)?;
        application_identifier.encode(encoder)?;
        team_identifier.encode(encoder)?;
        get_task_allow.encode(encoder)?;
        keychain_access_groups.encode(encoder)?;

        Ok(())
    }
}

impl FixedTag for Entitlements<'_> {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N16,
    };
}
