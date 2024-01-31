use cms::{
    builder::SignerInfoBuilder,
    cert::{x509::spki::AlgorithmIdentifier, IssuerAndSerialNumber},
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;

use crate::certificate::provisioning_certificate;

pub(crate) fn signer_info(
    content: &EncapsulatedContentInfo,
) -> SignerInfoBuilder<'static, SigningKey<Sha256>> {
    let provisioning_certificate = provisioning_certificate();

    SignerInfoBuilder::new(
        todo!(),
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: provisioning_certificate.tbs_certificate.issuer,
            serial_number: provisioning_certificate.tbs_certificate.serial_number,
        }),
        provisioning_certificate.signature_algorithm,
        content,
        todo!(),
    )
    .unwrap()
}
