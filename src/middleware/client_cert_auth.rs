use axum::extract::Request;
use axum::middleware::{AddExtension, Next};
use axum::response::Response;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use futures_util::future::BoxFuture;
use rustls_pki_types::CertificateDer;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::ServiceBuilder;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{OID_X509_GIVEN_NAME, OID_X509_SERIALNUMBER, OID_X509_SURNAME};
use x509_parser::prelude::FromDer;

#[derive(Clone)]
pub(crate) struct ClientCertData {
    pub given_name: String,
    pub surname: String,
    pub serial_number: String,
    pub country: String,
}

#[derive(Clone)]
pub(crate) struct PeerCertificates<'a>(Option<Vec<CertificateDer<'a>>>);

#[derive(Clone)]
pub(crate) struct AuthAcceptor {
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
        });
    } else {
        return Err("Missing client certificate");
    }

    Ok(next.run(request).await)
}
