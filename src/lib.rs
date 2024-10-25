#![warn(
    clippy::correctness,
    clippy::suspicious,
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::pedantic,
    clippy::nursery,
    warnings,
    deprecated_safe,
    future_incompatible,
    keyword_idents,
    let_underscore,
    nonstandard_style,
    refining_impl_trait,
    rust_2024_compatibility,
    unused,
    missing_docs
)]

//! A small library mostly for proof of concept, implementing the symmetric key package from [IETF RFC 6031](https://datatracker.ietf.org/doc/html/rfc6031)

use der::{
    asn1::{
        OctetString,
        SequenceOf,
        SetOfVec,
    },
    oid::ObjectIdentifier,
    Any,
    Sequence,
};

/// Taken from rfc 5652 page 14.
#[derive(Sequence)]
#[non_exhaustive]
pub struct Attribute
{
    /// The OID for identifying what the `attr_values`
    /// represents.
    pub attr_type:   ObjectIdentifier,
    /// The attributes values contained withing, can take
    /// any valid asn1 type.
    pub attr_values: SetOfVec<Any>,
}

/// Represents a CMS `ContentInfo` type with the context
/// specific asn1 tag attached to the child sequence. Equivalent to [this](https://datatracker.ietf.org/doc/html/rfc6031#section-2)
#[derive(Sequence)]
pub struct SymmetricKeyContentInfo
{
    /// The oid used to inform the nature of the content
    /// held within.
    pub id_ct_kp_s_key_package: ObjectIdentifier,
    /// The actual content of the content info struct, this
    /// will be contained within a context specific tag
    /// inside the asn1 as [defined here](https://datatracker.ietf.org/doc/html/rfc5652#section-3).
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub symmetric_key_package:  SymmetricKeyPackage,
}

type KeyPkgVersion = i64;

/// This contains a sequence of `OneSymmetricKey` asn1
/// objects and potentially relevant attributes.
#[derive(Sequence)]
pub struct SymmetricKeyPackage
{
    /// This is the version as defined by [RFC 6031](https://datatracker.ietf.org/doc/html/rfc6031#section-2) and the value should always be 1.
    pub version:         KeyPkgVersion,
    /// The potential attributes of the
    /// `SymmetricKeyPackage`
    pub s_key_pkg_attrs: Option<SequenceOf<Attribute, { usize::MAX }>>,
    /// The actual symmetric keys of the package.
    pub s_keys:          SequenceOf<OneSymmetricKey, { usize::MAX }>,
}

/// Represents a single symmetric key as [defined here](https://datatracker.ietf.org/doc/html/rfc6031#section-2)
#[derive(Sequence)]
pub struct OneSymmetricKey
{
    /// The attributes of the symmetric key.
    pub s_key_attrs: Option<SequenceOf<Attribute, { usize::MAX }>>,
    /// The actual key.
    pub s_key:       Option<OctetString>,
}
