mod app_state;
mod middleware;
mod routes;
mod solicitor;

use crate::app_state::AppState;
use crate::middleware::client_cert_auth::{AuthAcceptor, client_cert_middleware};
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Redirect;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8};
use once_common::oauth::pg_issuer::CoreRsaPrivateSigningKey;
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::version::TLS12;
use rustls::{RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{read, read_dir, read_to_string};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;
use webpki::aws_lc_rs::{
    ECDSA_P256_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA512, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

#[tokio::main]
async fn main() {
    let http = http_server();
    let https = https_server();
    tokio::join!(http, https);
}

async fn http_server() {
    let app = Router::new().fallback(redirect_to_https);
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn redirect_to_https(request: Request) -> Result<Redirect, StatusCode> {
    let host = request
        .headers()
        .get("host")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("localhost");
    let host = host.split(':').next().unwrap_or(host);
    let https_url = format!(
        "https://{}:8443{}",
        host,
        request
            .uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/")
    );

    Ok(Redirect::permanent(&https_url))
}

async fn https_server() {
    dotenvy::dotenv().expect("Failed to load environment variables.");
    env_logger::init();

    let assets_service = ServeDir::new("assets");

    let crypto_provider = create_crypto_provider();
    let root_cert_store = create_root_cert_store();
    let client_cert_verifier =
        create_client_cert_verifier(root_cert_store, crypto_provider.clone());
    let server_config = create_server_config(crypto_provider, client_cert_verifier);

    let db_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL environment variable not set.");
    let config = AsyncDieselConnectionManager::new(db_url);
    let db_pool = bb8::Pool::builder().build(config).await.unwrap();

    let jwt_private_key_path =
        dotenvy::var("JWT_PRIVATE_KEY").expect("JWT_PRIVATE_KEY environment variable not set.");
    let rsa_key = load_rsa_private_key(&PathBuf::from(&jwt_private_key_path));

    let issuer = dotenvy::var("JWT_ISSUER").expect("JWT_ISSUER environment variable not set.");
    let app_state = AppState::new(db_pool, rsa_key, issuer);

    let config = RustlsConfig::from_config(server_config);
    let app = Router::new()
        .merge(routes::create_routes())
        .nest_service("/assets", assets_service)
        .route_layer(axum::middleware::from_fn(client_cert_middleware))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    axum_server::bind(addr)
        .acceptor(AuthAcceptor::new(RustlsAcceptor::new(config)))
        .serve(app.into_make_service())
        .await
        .unwrap()
}

fn create_crypto_provider() -> Arc<CryptoProvider> {
    let mut crypto_provider = default_provider();
    crypto_provider.cipher_suites = vec![
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ];
    crypto_provider.signature_verification_algorithms = SUPPORTED_SIG_ALGORITHMS;
    Arc::new(crypto_provider)
}

fn create_client_cert_verifier(
    root_cert_store: Arc<RootCertStore>,
    crypto_provider: Arc<CryptoProvider>,
) -> Arc<dyn ClientCertVerifier> {
    WebPkiClientVerifier::builder_with_provider(root_cert_store, crypto_provider)
        .build()
        .unwrap()
}

fn create_server_config(
    crypto_provider: Arc<CryptoProvider>,
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
) -> Arc<ServerConfig> {
    let server_cert_path =
        dotenvy::var("SERVER_CERT").expect("SERVER_CERT environment variable not set.");
    let server_key_path =
        dotenvy::var("SERVER_KEY").expect("SERVER_KEY environment variable not set.");

    let server_certificate = if let Some(ext) = PathBuf::from(&server_cert_path)
        .extension()
        .and_then(|e| e.to_str())
    {
        load_certificate(ext, &PathBuf::from(&server_cert_path))
    } else {
        panic!("Server certificate file has no valid extension.");
    };

    let server_key = if let Some(ext) = PathBuf::from(&server_key_path)
        .extension()
        .and_then(|e| e.to_str())
    {
        if ext == "key" {
            PrivateKeyDer::from_pem_file(&server_key_path)
                .expect("Failed to parse server key file.")
        } else {
            panic!("The key file must have the extension .key");
        }
    } else {
        panic!("Server key file has no valid extension.");
    };

    let config = ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(vec![server_certificate], server_key)
        .unwrap();

    Arc::new(config)
}

fn create_root_cert_store() -> Arc<RootCertStore> {
    let certs_dir =
        dotenvy::var("DNIE_CERTS_DIR").expect("DNIE_CERTS_DIR environment variable not set.");
    let cert_files = read_dir(certs_dir).expect("Failed to read DNIE_CERTS_DIR.");
    let mut root_cert_store = RootCertStore::empty();

    for cert in cert_files.flatten() {
        if let Some(ext) = cert.path().extension().and_then(|e| e.to_str())
            && SUPPORTED_CERT_EXTENSIONS.contains(&ext)
        {
            add_certificate(&mut root_cert_store, ext, cert.path());
        }
    }

    Arc::new(root_cert_store)
}

fn add_certificate(root_cert_store: &mut RootCertStore, ext: &str, path: PathBuf) {
    match ext {
        "pem" => {
            root_cert_store
                .add(load_certificate(ext, &path))
                .expect("Failed to add PEM certificate to root store.");
        }
        "der" => {
            root_cert_store
                .add(load_certificate(ext, &path))
                .expect("Failed to add DER certificate to root store.");
        }
        _ => panic!("Invalid certificate extension: {}", ext),
    }
}

fn load_certificate<'a>(ext: &str, path: &PathBuf) -> CertificateDer<'a> {
    match ext {
        "pem" => CertificateDer::from_pem_file(path).expect("Failed to parse PEM file."),
        "der" => CertificateDer::from(read(path).expect("Failed to read DER file.")),
        _ => panic!("Invalid certificate extension: {}", ext),
    }
}

fn load_rsa_private_key(path: &PathBuf) -> CoreRsaPrivateSigningKey {
    let encoded_key = read_to_string(path).expect("Failed to read RSA private key file.");
    CoreRsaPrivateSigningKey::from_pem(&encoded_key, None)
        .expect("Failed to parse RSA private key file.")
}

static SUPPORTED_SIG_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA512,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA256,
    ],
    mapping: &[
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[RSA_PKCS1_2048_8192_SHA256],
        ),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
    ],
};

const SUPPORTED_CERT_EXTENSIONS: [&str; 2] = ["pem", "der"];
