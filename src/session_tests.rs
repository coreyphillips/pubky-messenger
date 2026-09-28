use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct ServerState {
    generation: AtomicUsize,
    reject_sessions: AtomicUsize,
    reject_mutations: AtomicBool,
    expired_waiters: std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

struct SessionServer {
    origin: String,
    state: Arc<ServerState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SessionServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SessionServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(ServerState::default());
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let state = shared.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let header_len;
                    loop {
                        let mut chunk = [0; 4096];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if let Some(end) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            header_len = end + 4;
                            break;
                        }
                    }
                    let headers =
                        String::from_utf8_lossy(&request[..header_len]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(str::trim)
                        .unwrap_or("0")
                        .parse()
                        .unwrap();
                    while request.len() < header_len + length {
                        let mut chunk = [0; 4096];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    let (status, cookie) = if headers.starts_with("post /session ") {
                        if state.reject_sessions.load(Ordering::SeqCst) != 0 {
                            (state.reject_sessions.load(Ordering::SeqCst), String::new())
                        } else {
                            let next = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
                            (200, format!("Set-Cookie: session={next}; Path=/\r\n"))
                        }
                    } else {
                        let expected = state.generation.load(Ordering::SeqCst);
                        let valid = headers
                            .lines()
                            .any(|line| line == format!("cookie: session={expected}"));
                        if !valid {
                            let barrier = state.expired_waiters.lock().unwrap().clone();
                            if let Some(barrier) = barrier {
                                barrier.wait().await;
                            }
                        }
                        let status = if valid && !state.reject_mutations.load(Ordering::SeqCst) {
                            200
                        } else {
                            401
                        };
                        (status, String::new())
                    };
                    let response = format!("HTTP/1.1 {status} Test\r\n{cookie}Content-Length: 0\r\nConnection: close\r\n\r\n");
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self {
            origin,
            state,
            task,
        }
    }

    fn transport(&self) -> PubkyTransport {
        PubkyTransport {
            http: reqwest::Client::builder()
                .no_proxy()
                .cookie_store(true)
                .build()
                .unwrap(),
            keypair: crate::test_server::keypair(1),
            session: Mutex::new(0),
            session_url: format!("{}/session", self.origin),
            metrics: RequestMetrics::default(),
        }
    }
}

#[tokio::test]
async fn concurrent_expired_mutations_share_one_session_refresh() {
    let server = SessionServer::start().await;
    let transport = server.transport();
    let url = format!("{}/message", server.origin);
    assert_eq!(
        transport
            .mutate_at(&url, Mutation::Put(b"same"))
            .await
            .unwrap()
            .status,
        200
    );
    server.state.generation.fetch_add(1, Ordering::SeqCst);
    *server.state.expired_waiters.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(2)));

    let results = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            transport.mutate_at(&url, Mutation::Put(b"same")),
            transport.mutate_at(&url, Mutation::Delete)
        )
    })
    .await
    .unwrap();
    assert_eq!(results.0.unwrap().status, 200);
    assert_eq!(results.1.unwrap().status, 200);
    let stats = transport.metrics.snapshot();
    assert_eq!(stats.session.attempts, 2);
    assert_eq!(stats.put.attempts, 3);
    assert_eq!(stats.delete.attempts, 2);
}

#[tokio::test]
async fn rejected_authentication_is_bounded_and_keeps_http_status() {
    let server = SessionServer::start().await;
    let transport = server.transport();
    let url = format!("{}/message", server.origin);
    server.state.reject_sessions.store(403, Ordering::SeqCst);
    assert_eq!(
        transport
            .mutate_at(&url, Mutation::Put(b"same"))
            .await
            .unwrap()
            .status,
        403
    );
    assert_eq!(transport.metrics.snapshot().put.attempts, 0);
    server.state.reject_sessions.store(0, Ordering::SeqCst);
    server.state.reject_mutations.store(true, Ordering::SeqCst);
    assert_eq!(
        transport
            .mutate_at(&url, Mutation::Put(b"same"))
            .await
            .unwrap()
            .status,
        401
    );
    let stats = transport.metrics.snapshot();
    assert_eq!(stats.session.attempts, 3);
    assert_eq!(stats.put.attempts, 2);
}

struct LocalMutationTransport<'a> {
    inner: &'a PubkyTransport,
    url: &'a str,
}

impl Transport for LocalMutationTransport<'_> {
    fn metrics(&self) -> &RequestMetrics {
        self.inner.metrics()
    }
    fn get<'a>(
        &'a self,
        _: &'a str,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(async { Err("no reads in this fixture".to_string()) })
    }
    fn put<'a>(
        &'a self,
        _: &'a str,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(self.inner.mutate_at(self.url, Mutation::Put(body)))
    }
    fn delete<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(self.inner.mutate_at(self.url, Mutation::Delete))
    }
}

#[tokio::test]
async fn a_missing_session_endpoint_is_not_a_successful_deletion() {
    let server = SessionServer::start().await;
    server.state.reject_sessions.store(404, Ordering::SeqCst);
    let transport = server.transport();
    let url = format!("{}/message", server.origin);
    let local = LocalMutationTransport {
        inner: &transport,
        url: &url,
    };
    let permits = request_permits(2);
    let config = FetchConfig::default();
    let failure = Requests::new(&local, &permits, &config)
        .delete("message")
        .await
        .unwrap_err();
    assert_eq!(failure.reason, FailureReason::Authentication(404));
    assert_eq!(failure.attempts, 1);
    assert_eq!(transport.metrics.snapshot().session.attempts, 1);
    assert_eq!(transport.metrics.snapshot().delete.attempts, 0);
}
