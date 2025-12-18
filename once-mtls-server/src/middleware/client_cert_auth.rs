use axum::Extension;
use axum::extract::Request;
use axum::middleware::{AddExtension, Next};
use axum::response::Response;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use chrono::{DateTime, NaiveDateTime, Utc};
use futures_util::future::BoxFuture;
use once_common::oauth::client_cert_data::ClientCertData;
use rustls_pki_types::CertificateDer;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::ServiceBuilder;
use x509_parser::asn1_rs::{Error, oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::parse_der;
use x509_parser::error::X509Error;
use x509_parser::nom::HexDisplay;
use x509_parser::oid_registry::{OID_X509_GIVEN_NAME, OID_X509_SERIALNUMBER, OID_X509_SURNAME};
use x509_parser::prelude::FromDer;
use x509_parser::x509::AttributeTypeAndValue;

#[derive(Clone)]
pub struct PeerCertificates<'a>(Option<Vec<CertificateDer<'a>>>);

#[derive(Clone)]
pub struct AuthAcceptor {
    inner: RustlsAcceptor,
}

impl AuthAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for AuthAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, PeerCertificates<'static>>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, io_stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (io_stream, service) = acceptor.accept(io_stream, service).await?;
            let server_conn = io_stream.get_ref().1;
            let peer_certificates =
                PeerCertificates(server_conn.peer_certificates().map(From::from));
            let service = ServiceBuilder::new()
                .layer(Extension(peer_certificates))
                .service(service);

            Ok((io_stream, service))
        })
    }
}

pub async fn client_cert_middleware(
    Extension(peer_certificates): Extension<PeerCertificates<'_>>,
    mut request: Request,
    next: Next,
) -> Result<Response, &'static str> {
    if let Some(peer_certificates) = peer_certificates.0 {
        let x509 = X509Certificate::from_der(
            peer_certificates
                .first()
                .ok_or("Missing client certificate")?,
        )
        .map_err(|_| "Invalid client certificate")?
        .1;

        let dob_ext = x509
            .extensions()
            .iter()
            .find(|&x| x.oid == oid!(2.5.29.9))
            .ok_or("Missing DOB extension")?;

        let (_, dob_der) = parse_der(dob_ext.value)
            .ok()
            .ok_or("Failed to parse DOB extension")?;

        let dob_attrs = match dob_der.content {
            BerObjectContent::Sequence(ref items) => items,
            _ => return Err("Invalid DOB extension"),
        };

        let mut date_of_birth: Option<DateTime<Utc>> = None;

        for dob_attr in dob_attrs {
            let attr_seq = match dob_attr.content {
                BerObjectContent::Sequence(ref items) => items,
                _ => continue,
            };

            let attr_type = &attr_seq[0];
            let attr_type_oid = match attr_type.content {
                BerObjectContent::OID(ref oid) => oid,
                _ => continue,
            };

            if *attr_type_oid != oid!(1.3.6.1.5.5.7.9.1) {
                continue;
            }

            let values_set = &attr_seq[1];
            let values = match values_set.content {
                BerObjectContent::Set(ref items) if !items.is_empty() => items,
                _ => return Err("Invalid DOB extension"),
            };

            let v0 = &values[0];
            let gen_time_str = match v0.content {
                BerObjectContent::GeneralizedTime(ref time) => time.to_string(),
                _ => return Err("Invalid DOB extension"),
            };

            date_of_birth = Some(DateTime::from_naive_utc_and_offset(
                NaiveDateTime::parse_from_str(&gen_time_str, "%Y%m%d%H%M%SZ")
                    .map_err(|_| "Invalid DOB extension")?,
                Utc,
            ));
            break;
        }

        let given_name = x509
            .subject
            .iter_by_oid(&OID_X509_GIVEN_NAME)
            .next()
            .ok_or("Missing given name")?
            .as_str()
            .map_err(|_| "Invalid given name")?;
        let surname = x509
            .subject
            .iter_by_oid(&OID_X509_SURNAME)
            .next()
            .ok_or("Missing surname")?
            .as_str()
            .map_err(|_| "Invalid surname")?;
        let country = x509
            .subject
            .iter_country()
            .next()
            .ok_or("Missing country")?
            .as_str()
            .map_err(|_| "Invalid country")?;
        let serial_number = x509
            .subject()
            .iter_by_oid(&OID_X509_SERIALNUMBER)
            .next()
            .ok_or("Missing serial number")?
            .as_str()
            .map_err(|_| "Invalid serial number")?;

        request.extensions_mut().insert(ClientCertData {
            given_name: given_name.to_string(),
            surname: surname.to_string(),
            country: country.to_string(),
            serial_number: serial_number.to_string(),
            date_of_birth: date_of_birth.ok_or("Missing DOB")?,
        });
    } else {
        return Err("Missing client certificate");
    }

    Ok(next.run(request).await)
}
