//! Outgoing HTTPS and WebSockets (other sites, push services, release checks, the SNIP forum):
//! which certificate authorities they trust. The usual public ones (Mozilla's list, built in),
//! and any in the PEM file EXTRA_CA_CERTS names: sites that talk over a local network with their
//! own authority (docs/SELF_HOSTING.md) trust each other's that way. NODE_EXTRA_CA_CERTS, which
//! the Node.js server read for this, works too, so a site that set it keeps working.
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

/// The file of extra authorities, if one is set.
pub fn extra_file() -> Option<String> {
    ["EXTRA_CA_CERTS", "NODE_EXTRA_CA_CERTS"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// Client settings that trust the public authorities and those in `extra` (a PEM file). A file
/// that can't be read is reported and left out, as Node.js did.
pub fn build(extra: Option<&Path>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(file) = extra {
        match std::fs::read(file) {
            Ok(pem) => {
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok).collect();
                let (added, _) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    eprintln!("Warning: no certificates found in {} (EXTRA_CA_CERTS)", file.display());
                }
            }
            Err(e) => eprintln!("Warning: ignoring extra certificates from {}: {e}", file.display()),
        }
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The settings every outgoing connection uses (made once, from the environment).
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| Arc::new(build(extra_file().as_deref().map(Path::new)))).clone()
}

/// An HTTP client that uses those settings.
pub fn agent() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new().tls_config(client_config())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;

    /// A certificate authority of our own and a certificate it signed for localhost (openssl).
    fn authority(dir: &Path) -> Option<()> {
        let run = |args: &[&str]| Command::new("openssl").args(args).current_dir(dir).output().is_ok_and(|o| o.status.success());
        let ok = run(&["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Test authority"])
            && std::fs::write(dir.join("ext.cnf"), "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\n").is_ok()
            && run(&["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "site.key", "-out", "site.csr", "-subj", "/CN=localhost"])
            && run(&["x509", "-req", "-in", "site.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "site.pem", "-days", "2", "-extfile", "ext.cnf"]);
        ok.then_some(())
    }

    /// An HTTPS server on localhost that answers "ok" to each request.
    fn serve(dir: &Path) -> u16 {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(dir.join("site.pem")).unwrap().map(Result::unwrap).collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(dir.join("site.key")).unwrap();
        let config = Arc::new(rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(certs, key).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut tcp in listener.incoming().flatten() {
                let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else { continue };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut buf = [0u8; 4096];
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    let _ = tls.flush();
                }
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        port
    }

    #[test]
    fn extra_authorities_are_trusted_and_only_then() {
        let dir = tempfile::tempdir().unwrap();
        if authority(dir.path()).is_none() {
            eprintln!("skipped: needs openssl");
            return;
        }
        let port = serve(dir.path());
        let get = |config: rustls::ClientConfig| {
            let agent = ureq::AgentBuilder::new().tls_config(Arc::new(config)).timeout(std::time::Duration::from_secs(5)).build();
            agent.get(&format!("https://localhost:{port}/")).call().map(|r| r.into_string().unwrap_or_default()).map_err(|e| e.to_string())
        };
        assert_eq!(get(build(Some(&dir.path().join("ca.pem")))), Ok("ok".to_string()));
        // The public authorities alone don't know it.
        let refused = get(build(None)).unwrap_err();
        assert!(refused.contains("UnknownIssuer") || refused.contains("invalid peer certificate"), "{refused}");
        // A file that isn't there, or holds no certificate, is left out (and said so).
        assert!(get(build(Some(&dir.path().join("missing.pem")))).is_err());
        assert!(get(build(Some(&dir.path().join("ext.cnf")))).is_err());
    }
}
