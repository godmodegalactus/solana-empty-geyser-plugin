use std::net::IpAddr;

use pkcs8::{AlgorithmIdentifier, ObjectIdentifier, der::Document};
use rcgen::{RcgenError, CertificateParams, SanType, DistinguishedName, DnType};
use solana_sdk::{signature::Keypair, pubkey::Pubkey};
use x509_parser::{prelude::{X509Certificate, FromDer}, public_key::PublicKey};

pub fn new_self_signed_tls_certificate(
    keypair: &Keypair,
    san: IpAddr,
) -> Result<(rustls::Certificate, rustls::PrivateKey), RcgenError> {
    const ED25519_IDENTIFIER: [u32; 4] = [1, 3, 101, 112];
    let mut private_key = Vec::<u8>::with_capacity(34);
    private_key.extend_from_slice(&[0x04, 0x20]); // ASN.1 OCTET STRING
    private_key.extend_from_slice(keypair.secret().as_bytes());
    let key_pkcs8 = pkcs8::PrivateKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: ObjectIdentifier::from_arcs(&ED25519_IDENTIFIER).expect("Failed to convert OID"),
            parameters: None,
        },
        private_key: &private_key,
        public_key: None,
    };
    let key_pkcs8_der = key_pkcs8
        .to_der()
        .expect("Failed to convert keypair to DER")
        .to_der();

    let rcgen_keypair = rcgen::KeyPair::from_der(&key_pkcs8_der)?;

    let mut cert_params = CertificateParams::default();
    cert_params.subject_alt_names = vec![SanType::IpAddress(san)];
    cert_params.alg = &rcgen::PKCS_ED25519;
    cert_params.key_pair = Some(rcgen_keypair);
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, "Solana node");

    let cert = rcgen::Certificate::from_params(cert_params)?;
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    Ok((rustls::Certificate(cert_der), priv_key))
}

pub fn get_pubkey_from_tls_certificate(der_cert: &rustls::Certificate) -> Option<Pubkey> {
    let (_, cert) = X509Certificate::from_der(der_cert.as_ref()).ok()?;
    match cert.public_key().parsed().ok()? {
        PublicKey::Unknown(key) => Pubkey::try_from(key).ok(),
        _ => None,
    }
}