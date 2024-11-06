use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid XML")]
    InvalidXml,
    #[error("Parse error")]
    ParseError,
    #[error("Parse int error")]
    ParseIntError,
    #[error("Parse Uuid error")]
    ParseUuidError,
    #[error("Schema file not found")]
    SchemaFileNotFound,
    #[error("Schema validation failed")]
    SchemaValidationFailed,
    #[error("Schema file corrupt")]
    SchemaFileCorrupt,
    #[error("Unknown CPL type")]
    UnknownCplType,
    #[error("DateTime parse error")]
    DateParseError,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Signature invalid")]
    SignatureInvalid,
    #[error("Certificate expired")]
    CertificateExpired,
    #[error("Certificate not yet valid")]
    CertificateNotYetValid,
    #[error("Unable to get certificate issuer")]
    CertificateIssuer,
    #[error("Certificate verify failed")]
    CertificateVerifyFailed,
    #[error("File not found")]
    FileNotFound,
    #[error("Key decryption failed")]
    KeyDecryptionFailed,
    #[error("Unknown KDM structure id")]
    UnknownKdmStructureId,
    #[error("Malformed key type")]
    KeyTypeMalformed,
    #[error("Certificate load failed")]
    CertificateLoadFailed,
    #[error("Key load failed")]
    KeyLoadFailed,
    #[error("XmlSecError {0:?}")]
    XmlSecError(#[from] xmlsec::XmlSecError),
    #[error("OpenSSL error {0:?}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
    #[error("Certificate read/convert failed")]
    CertificateReadFailed,
    #[error("Key not set")]
    KeyNotSet,
    #[error("Root node missing in XML document")]
    MissingRootNode,
    #[error("Hash creation error")]
    HashCreationError,
    #[error("XmlSecErrorCollector can only be created once per thread")]
    XmlSecErrorCollectorAlreadyExists,
    #[error("Signer certificate not found")]
    CertificateNotFound,
    #[error("CPL Write Error to CplKdm Store")]
    CplWriteError,
    #[error("CPL not found in CPLKdm Store")]
    CplNotFound,
    #[error("KDM already exists in CPLKdm Store")]
    KdmAlreadyExists,
    #[error("Failed to parse forensic marking flag: {0}")]
    ForensicMarkingFlagParseError(String),
    #[error("Unknown forensic marking flag: {0}")]
    UnknownForensicMarkingFlag(String),
    #[error("Main asset not found")]
    MainAssetNotFound,
}
