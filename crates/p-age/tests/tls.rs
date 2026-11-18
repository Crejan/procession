//! The same lines inside real TLS 1.3 (rustls, the `ring` provider), over in-memory streams: the
//! sandbox cannot bind TCP ports, so the TCP listener (`net::listen`) was never run here.

mod common;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use p_act::Document;
use p_act::exchange::{ClearancePolicy, Message};
use p_age::net::{Lines, serve_tls};
use p_age::tls::{EXPORTER_LABEL, client_config, server_config};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncWriteExt, duplex};
use tokio_rustls::TlsConnector;

struct Pki {
    root_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["broker.test".to_owned()]).unwrap();
    let server = server_params.signed_by(&server_key, &Issuer::new(ca_params, &ca_key)).unwrap();
    Pki { root_pem: ca.pem(), server_cert_pem: server.pem(), server_key_pem: server_key.serialize_pem() }
}

fn acceptor(p: &Pki) -> tokio_rustls::TlsAcceptor {
    tokio_rustls::TlsAcceptor::from(server_config(p.server_cert_pem.as_bytes(), p.server_key_pem.as_bytes()).unwrap())
}

#[tokio::test]
async fn a_pledge_signs_in_over_tls_with_the_binding_both_ends_export() {
    let w = World::new();
    let p = pki();
    let (client_end, server_end) = duplex(1 << 20);
    tokio::spawn(serve_tls(server_end, acceptor(&p), Arc::clone(&w.broker)));
    let connector = TlsConnector::from(client_config(p.root_pem.as_bytes()).unwrap());
    let tls = connector.connect(ServerName::try_from("broker.test").unwrap(), client_end).await.unwrap();
    assert_eq!(tls.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    let mut binding = [0u8; 32];
    tls.get_ref().1.export_keying_material(&mut binding, EXPORTER_LABEL, None).unwrap();
    let (rd, wr) = tokio::io::split(tls);
    let mut lines = Lines::new(rd, std::time::Duration::from_secs(5));
    let mut wr = wr;

    wr.write_all(b"{\"schema_version\":1,\"type\":\"hello\"}\n").await.unwrap();
    let challenge: serde_json::Value = serde_json::from_slice(&lines.read(None).await.unwrap().unwrap()).unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    // the signature is over the binding of this connection: it is accepted here
    let line = signin_message("jan", &w.jan_connection, nonce, binding);
    wr.write_all(&[serde_json::to_vec(&line).unwrap(), b"\n".to_vec()].concat()).await.unwrap();
    let ready: serde_json::Value = serde_json::from_slice(&lines.read(None).await.unwrap().unwrap()).unwrap();
    assert_eq!(ready["type"], "ready");
}

#[tokio::test]
async fn a_sign_in_made_for_another_tls_connection_is_refused() {
    let w = World::new();
    let p = pki();
    let (client_end, server_end) = duplex(1 << 20);
    tokio::spawn(serve_tls(server_end, acceptor(&p), Arc::clone(&w.broker)));
    let connector = TlsConnector::from(client_config(p.root_pem.as_bytes()).unwrap());
    let tls = connector.connect(ServerName::try_from("broker.test").unwrap(), client_end).await.unwrap();
    let (rd, mut wr) = tokio::io::split(tls);
    let mut lines = Lines::new(rd, std::time::Duration::from_secs(5));
    wr.write_all(b"{\"schema_version\":1,\"type\":\"hello\"}\n").await.unwrap();
    let challenge: serde_json::Value = serde_json::from_slice(&lines.read(None).await.unwrap().unwrap()).unwrap();
    // a binding exported from some other connection (here: made up), correctly signed
    let doc = connection_doc("jan", challenge["nonce"].as_str().unwrap(), [9u8; 32]).as_bytes().to_vec();
    let sig = p_act::sign::sign_connection(&p_act::sign::Signer::plain(&w.jan_connection), &doc).unwrap();
    let line = serde_json::json!({"schema_version":1,"type":"signin","doc":STANDARD.encode(&doc),"doc_sig":p_act::sign::signature_to_base64(&sig)});
    wr.write_all(&[serde_json::to_vec(&line).unwrap(), b"\n".to_vec()].concat()).await.unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&lines.read(None).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["error"], "signin");
}

#[tokio::test]
async fn a_service_talks_to_the_broker_over_tls_and_a_wrong_root_is_not_trusted() {
    let w = World::new();
    let p = pki();
    let (client_end, server_end) = duplex(1 << 20);
    tokio::spawn(serve_tls(server_end, acceptor(&p), Arc::clone(&w.broker)));
    let connector = TlsConnector::from(client_config(p.root_pem.as_bytes()).unwrap());
    let tls = connector.connect(ServerName::try_from("broker.test").unwrap(), client_end).await.unwrap();
    let (rd, mut wr) = tokio::io::split(tls);
    let mut lines = Lines::new(rd, std::time::Duration::from_secs(5));
    // the delegation is not registered here, so the answer is a refusal: the exchange works through TLS
    let submit = w.submit(1, 120);
    wr.write_all(&submit_line(&submit)).await.unwrap();
    let line = lines.read(None).await.unwrap().unwrap();
    let Message::Answer(answer) = Message::parse(&line, ClearancePolicy::Required).unwrap() else {
        panic!("an answer")
    };
    assert_eq!(answer.request, hash_of(&submit));

    // a client that trusts another root refuses the broker
    let other = pki();
    let (client_end, server_end) = duplex(1 << 20);
    tokio::spawn(serve_tls(server_end, acceptor(&p), Arc::clone(&w.broker)));
    let wrong = TlsConnector::from(client_config(other.root_pem.as_bytes()).unwrap());
    assert!(wrong.connect(ServerName::try_from("broker.test").unwrap(), client_end).await.is_err());
    // and a client that asks for another name
    let (client_end, server_end) = duplex(1 << 20);
    tokio::spawn(serve_tls(server_end, acceptor(&p), Arc::clone(&w.broker)));
    assert!(connector.connect(ServerName::try_from("elsewhere.test").unwrap(), client_end).await.is_err());
}
