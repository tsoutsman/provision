use cms::cert::x509::{
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
    time::Validity,
    TbsCertificate,
};
use der::asn1::{Any, SequenceOf, SetOfVec, Utf8StringRef};

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

fn string(s: &str) -> Utf8StringRef {
    Utf8StringRef::new(s).unwrap()
}

fn der() {
    let mut set = SetOfVec::<Any>::new();

    // TODO
    set.insert(kv!("IsXcodeManaged", true)).unwrap();

    set.insert(kv!("LocalProvision", true)).unwrap();

    set.insert(kv!("TeamName", string("Klimenty Tsoutsman")))
        .unwrap();
}
