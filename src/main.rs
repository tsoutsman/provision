mod certificate;
mod content;
mod der;
mod device;
mod signer;

use std::{env, process::Command};

use cms::{
    cert::x509::{
        der::{asn1::SetOfVec, Any, Decode},
        spki::ObjectIdentifier,
    },
    content_info::{CmsVersion, ContentInfo},
    signed_data::SignedData,
};

use crate::certificate::provisioning_certificate;

const PKCS7_SIGNED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

fn main() {
    #[cfg(not(target_os = "macos"))]
    compile_error!("only macos is supported");

    let mut args = env::args();
    args.next().unwrap();

    let encaspulated_content_info = content::encapsulated_content_info();
    let signer_infos = signer::signer_infos(&encaspulated_content_info);

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::new(),
        encap_content_info: encaspulated_content_info,
        certificates: None,
        crls: None,
        signer_infos,
    };

    let content_info = ContentInfo {
        content_type: PKCS7_SIGNED_DATA_OID,
        content: Any::encode_from(&signed_data).unwrap(),
    };

    // TODO: Save to file
    println!("{content_info:?}");
}

// let file_path: PathBuf = args.next().unwrap().into();
// let bytes = std::fs::read(file_path).unwrap();
// let content_info = ContentInfo::from_der(&bytes).unwrap();
// let signed_data = content_info.content.decode_as::<SignedData>();
// println!("{signed_data:?}");
