use crate::app_state::AppState;
use axum::Router;
use diesel_async::pooled_connection::{bb8, AsyncDieselConnectionManager};
use once_common::oauth::pg_issuer::CoreRsaPrivateSigningKey;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::TLS12;
use rustls::ServerConfig;
use std::fs::{read, read_to_string};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};

mod app_state;
mod routes;

#[tokio::main]
async fn main() {
    https_server().await;
}

async fn https_server() {
    dotenvy::dotenv().expect("Failed to load environment variables.");
    env_logger::init();

    let server_config = create_server_config(Arc::new(default_provider()));

    let db_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL environment variable not set");
    let config = AsyncDieselConnectionManager::new(db_url);
    let db_pool = bb8::Pool::builder().build(config).await.unwrap();

    let jwt_private_key_path =
        dotenvy::var("JWT_PRIVATE_KEY").expect("JWT_PRIVATE_KEY environment variable not set.");
    let rsa_key = load_rsa_private_key(&PathBuf::from(&jwt_private_key_path));

    let issuer = dotenvy::var("JWT_ISSUER").expect("JWT_ISSUER environment variable not set.");

    let app_state = AppState::new(db_pool, rsa_key, issuer);

    let app = Router::new()
        .merge(routes::create_routes())
        .with_state(app_state);
    
    let rustls_config = RustlsConfig::from_config(server_config);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8444));
    axum_server::bind(addr)
        .acceptor(RustlsAcceptor::new(rustls_config))
        .serve(app.into_make_service())
        .await
        .unwrap()
}

fn create_server_config(crypto_provider: Arc<CryptoProvider>) -> Arc<ServerConfig> {
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
        .with_no_client_auth()
        .with_single_cert(vec![server_certificate], server_key)
        .unwrap();

    Arc::new(config)
}

fn load_rsa_private_key(path: &PathBuf) -> CoreRsaPrivateSigningKey {
    let encoded_key = read_to_string(path).expect("Failed to read RSA private key file.");
    CoreRsaPrivateSigningKey::from_pem(&encoded_key, None)
        .expect("Failed to parse RSA private key file.")
}

fn load_certificate<'a>(ext: &str, path: &PathBuf) -> CertificateDer<'a> {
    match ext {
        "pem" => CertificateDer::from_pem_file(path).expect("Failed to parse PEM file."),
        "der" => CertificateDer::from(read(path).expect("Failed to read DER file.")),
        _ => panic!("Invalid certificate extension: {}", ext),
    }
}
