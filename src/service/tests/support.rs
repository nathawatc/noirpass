use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;

use crate::gpg::{Gpg, parse_recipient_cert, test_support::TestGnupg};
use crate::store::Store;
use zbus::connection::Builder;
use zbus::export::futures_core::Stream;

use super::super::{SERVICE_PATH, Service, ServiceState};

/// Build a state around a temp store and a hermetic `GnuPG` home.
pub(in crate::service) fn test_state(
    gnupg: &TestGnupg,
    dir: &std::path::Path,
) -> Arc<ServiceState> {
    let store = Store::open(dir).unwrap();
    store.ensure_default().unwrap();
    let cert = parse_recipient_cert(&gnupg.export_public_binary()).unwrap();
    let gpg = Gpg::from_cert_with_homedir(cert, Some(gnupg.path().to_path_buf())).unwrap();
    ServiceState::new(store, gpg)
}

/// In-process p2p bus serving the real `Service` interface.
pub(super) async fn p2p_pair(state: Arc<ServiceState>) -> (zbus::Connection, zbus::Connection) {
    let guid = zbus::Guid::generate();
    let (p0, p1) = tokio::net::UnixStream::pair().unwrap();
    let server = Builder::unix_stream(p0)
        .server(guid)
        .unwrap()
        .p2p()
        .serve_at(SERVICE_PATH, Service::new(state))
        .unwrap()
        .build();
    let client = Builder::unix_stream(p1).p2p().build();
    let (server, client) = tokio::join!(server, client);
    (server.unwrap(), client.unwrap())
}

pub(super) async fn next_stream_item<S>(stream: &mut S) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
}

/// Poll admission once, then cancel only the caller future while its owned task waits.
pub(super) async fn admit_then_cancel(future: impl Future) {
    tokio::pin!(future);
    poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}
