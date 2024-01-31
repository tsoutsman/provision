mod certificate;
mod content;
mod device;
mod signer;

use std::env;

use cms::{
    builder::SignedDataBuilder,
    cert::x509::{der::Any, spki::ObjectIdentifier},
    content_info::ContentInfo,
};

use crate::device::devices;

const PKCS7_SIGNED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

fn main() {
    #[cfg(not(target_os = "macos"))]
    compile_error!("only macos is supported");

    let mut args = env::args();
    args.next().unwrap();

    let encaspulated_content_info = content::encapsulated_content_info();
    let signer_info = signer::signer_info(&encaspulated_content_info);

    let signed_data = SignedDataBuilder::new(&encaspulated_content_info)
        .add_signer_info(signer_info)
        .unwrap()
        .build()
        .unwrap();

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
