//! `indexone-revocation-http` — the HTTP transport for remote revocation.
//!
//! A concrete [`SnapshotSource`] that fetches a [`SignedRevocationSnapshot`]
//! from a revocation-log URL over blocking HTTP (`minreq` — no async runtime).
//! It lives in its own crate so `core/revocation` stays synchronous and
//! dependency-light; wire it in with
//! `SnapshotChecker::new(Box::new(HttpSnapshotSource::new(url)), operator_key, clock, max_staleness)`.
//!
//! The verification (signature, epoch anti-rollback, freshness) all happens in
//! `SnapshotChecker` — this crate only performs the fetch and hands back the
//! signed snapshot (or a transport error, which fails the checker closed).

use indexone_revocation::{SignedRevocationSnapshot, SnapshotSource};

/// Fetches the current signed revocation snapshot from `url`.
pub struct HttpSnapshotSource {
    url: String,
    timeout_secs: u64,
}

impl HttpSnapshotSource {
    /// A source pointed at a revocation-log endpoint that serves a
    /// `SignedRevocationSnapshot` as JSON. Default timeout is 10s.
    pub fn new(url: impl Into<String>) -> Self {
        HttpSnapshotSource {
            url: url.into(),
            timeout_secs: 10,
        }
    }

    /// Override the request timeout (seconds).
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

impl SnapshotSource for HttpSnapshotSource {
    fn fetch(&self) -> Result<SignedRevocationSnapshot, String> {
        let resp = minreq::get(&self.url)
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout_secs)
            .send()
            .map_err(|e| format!("revocation snapshot fetch failed: {e}"))?;
        if !(200..300).contains(&resp.status_code) {
            return Err(format!("revocation log returned HTTP {}", resp.status_code));
        }
        resp.json::<SignedRevocationSnapshot>()
            .map_err(|e| format!("malformed revocation snapshot: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_crypto::{Algorithm, Ed25519Signer, Signature, Signer};
    use indexone_revocation::{
        FixedClock, RevocationChecker, RevocationId, RevocationStatus, SnapshotChecker,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn revocation_id(tag: u8) -> RevocationId {
        RevocationId::from_signature(&Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![tag; 64],
        })
    }

    /// Serve `body` as JSON to every incoming connection until the test ends.
    /// A tiny std-only HTTP/1.1 responder — no framework, deterministic.
    fn serve(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf); // drain the request line/headers
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/witness/v1/revocations")
    }

    #[test]
    fn http_source_feeds_a_checker_that_answers_over_the_wire() {
        let operator = Ed25519Signer::from_seed([50u8; 32]);
        let revoked = revocation_id(2);
        let live = revocation_id(5);
        let snapshot = SignedRevocationSnapshot::sign(
            &operator,
            1,
            1_000,
            std::iter::once(revoked.clone()).collect(),
        );
        let url = serve(serde_json::to_string(&snapshot).unwrap());

        // Direct fetch: the transport returns the signed snapshot verbatim.
        let source = HttpSnapshotSource::new(&url).with_timeout(5);
        let fetched = source.fetch().unwrap();
        assert_eq!(fetched.epoch, 1);
        assert!(fetched.verify_signature(&operator.public_key()));

        // Wired into a checker: a real remote revocation lookup over HTTP.
        let checker = SnapshotChecker::new(
            Box::new(HttpSnapshotSource::new(&url)),
            operator.public_key(),
            FixedClock(1_100),
            3_600,
        );
        assert!(matches!(
            checker.is_revoked(&revoked).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
        assert_eq!(checker.is_revoked(&live).unwrap(), RevocationStatus::Live);
    }

    #[test]
    fn unreachable_url_fails_closed() {
        // Nothing listening → the transport errors, and the checker treats it as
        // "couldn't determine" (fail closed), never as "live".
        let source = HttpSnapshotSource::new("http://127.0.0.1:1/none").with_timeout(1);
        assert!(source.fetch().is_err());
    }
}
