//! Homeserver stand-in for unit tests

use futures::future::BoxFuture;
use pkarr::{Keypair, PublicKey};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

use crate::crypto::ConversationKey;
use crate::message::PrivateMessage;
use crate::metrics::{RequestKind, RequestMetrics};
use crate::receive::{HttpResponse, Transport};

type AfterRequest = Box<dyn FnOnce(&FakeServer) + Send>;

#[derive(Clone)]
pub enum Reply {
    /// A file's body, or a directory's entries one per line
    Body(String),
    Status(u16),
    RateLimited {
        retry_after_secs: u64,
    },
    Hang,
    Broken,
    StoredThenBroken,
}

/// Serves files and paged directory listings with injected latency, and records concurrency,
/// attempts (of reads and deletes) and request counts
#[derive(Default)]
pub struct FakeServer {
    /// Replies per URL without its query, one per attempt, the last one repeating. Unknown URLs
    /// are 404.
    routes: Mutex<HashMap<String, Vec<Reply>>>,
    /// Scripted DELETE responses, independent of the file bodies served by GET
    delete_routes: Mutex<HashMap<String, Vec<Reply>>>,
    put_routes: Mutex<HashMap<String, Vec<Reply>>>,
    metrics: RequestMetrics,
    pub delays: HashMap<String, Duration>,
    pub latency: Duration,
    /// Serve the first page of every listing, whatever the cursor
    pub ignores_cursor: bool,
    pub state: Mutex<ServerState>,
    /// Runs once, when the request for this URL (including its query) completes
    after: Mutex<Option<(String, AfterRequest)>>,
}

#[derive(Default)]
pub struct ServerState {
    pub in_flight: usize,
    pub peak: usize,
    in_flight_by_conversation: HashMap<String, usize>,
    pub peak_by_conversation: HashMap<String, usize>,
    /// Attempts per URL, including its query
    attempts: HashMap<String, usize>,
    starts: Vec<(Instant, String)>,
    pub requests: usize,
    pub listing_requests: usize,
    pub message_requests: usize,
    /// Message requests answered with a body
    pub bodies_sent: usize,
    pub not_modified: usize,
    /// URLs removed by successful deletes, in order
    pub deleted: Vec<String>,
    pub put_bodies: Vec<(String, Vec<u8>)>,
}

struct InFlight<'a> {
    server: &'a FakeServer,
    conversation: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut state = self.server.state.lock().unwrap();
        state.in_flight -= 1;
        *state
            .in_flight_by_conversation
            .get_mut(&self.conversation)
            .unwrap() -= 1;
    }
}

impl FakeServer {
    pub fn with_latency(latency: Duration) -> Self {
        Self {
            latency,
            ..Self::default()
        }
    }

    /// Serve messages under `author`'s copy of the conversation as `0000.json`, `0001.json`...,
    /// replacing whatever that directory held
    pub fn publish(
        &self,
        author: &Keypair,
        other: &PublicKey,
        messages: &[(u64, &str)],
    ) -> Vec<String> {
        self.reply(&directory(author, other), vec![Reply::Body(String::new())]);
        messages
            .iter()
            .enumerate()
            .map(|(i, (timestamp, content))| {
                self.add(
                    author,
                    other,
                    &format!("{:04}.json", i),
                    *timestamp,
                    content,
                )
            })
            .collect()
    }

    /// Serve one more message under `author`'s copy of the conversation
    pub fn add(
        &self,
        author: &Keypair,
        other: &PublicKey,
        name: &str,
        timestamp: u64,
        content: &str,
    ) -> String {
        let directory = directory(author, other);
        let url = format!("{}{}", directory, name);
        let message = PrivateMessage::new_at(author, other, content, timestamp).unwrap();
        self.reply(
            &url,
            vec![Reply::Body(serde_json::to_string(&message).unwrap())],
        );

        let mut entries = self.entries(&directory);
        entries.push(url.clone());
        self.reply(&directory, vec![Reply::Body(entries.join("\n"))]);
        url
    }

    /// Delete a message and its listing entry
    pub fn remove(&self, url: &str) {
        self.routes.lock().unwrap().remove(url);
        let directory = &url[..url.rfind('/').unwrap() + 1];
        let entries: Vec<String> = self
            .entries(directory)
            .into_iter()
            .filter(|entry| entry != url)
            .collect();
        self.reply(directory, vec![Reply::Body(entries.join("\n"))]);
    }

    /// Add entries to a directory's listing without serving anything at them
    pub fn list_unserved(&self, directory: &str, extra: &[String]) {
        let mut entries = self.entries(directory);
        entries.extend_from_slice(extra);
        self.reply(directory, vec![Reply::Body(entries.join("\n"))]);
    }

    pub fn reply(&self, url: &str, replies: Vec<Reply>) {
        self.routes.lock().unwrap().insert(url.to_string(), replies);
    }

    pub fn reply_delete(&self, url: &str, replies: Vec<Reply>) {
        self.delete_routes
            .lock()
            .unwrap()
            .insert(url.to_string(), replies);
    }

    pub fn reply_put(&self, url: &str, replies: Vec<Reply>) {
        self.put_routes
            .lock()
            .unwrap()
            .insert(url.to_string(), replies);
    }

    /// First reply body served at `url`
    pub fn body(&self, url: &str) -> String {
        match &self.routes.lock().unwrap()[url][0] {
            Reply::Body(body) => body.clone(),
            _ => panic!("{} has no body", url),
        }
    }

    fn entries(&self, directory: &str) -> Vec<String> {
        match self.routes.lock().unwrap().get(directory).map(|r| &r[0]) {
            Some(Reply::Body(body)) => body.lines().map(String::from).collect(),
            _ => Vec::new(),
        }
    }

    /// Run `action` once the request for `url`, including its query, completes
    pub fn after_request(&self, url: &str, action: impl FnOnce(&FakeServer) + Send + 'static) {
        *self.after.lock().unwrap() = Some((url.to_string(), Box::new(action)));
    }

    pub fn attempts(&self, url: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .attempts
            .get(url)
            .copied()
            .unwrap_or(0)
    }

    pub fn starts_of(&self, url: &str) -> Vec<Instant> {
        let state = self.state.lock().unwrap();
        state
            .starts
            .iter()
            .filter(|(_, u)| u == url)
            .map(|(t, _)| *t)
            .collect()
    }

    /// Reset every count except attempts, which select replies
    pub fn reset_counts(&self) {
        let mut state = self.state.lock().unwrap();
        *state = ServerState {
            attempts: std::mem::take(&mut state.attempts),
            ..ServerState::default()
        };
    }

    fn begin(&self, url: &str) -> (usize, InFlight<'_>) {
        let conversation = url
            .split("/private_messages/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default()
            .to_string();

        let mut state = self.state.lock().unwrap();
        state.requests += 1;
        if url.split('?').next().unwrap().ends_with('/') {
            state.listing_requests += 1;
        } else {
            state.message_requests += 1;
        }
        state.in_flight += 1;
        state.peak = state.peak.max(state.in_flight);
        let in_conversation = state
            .in_flight_by_conversation
            .entry(conversation.clone())
            .or_default();
        *in_conversation += 1;
        let in_conversation = *in_conversation;
        let peak = state
            .peak_by_conversation
            .entry(conversation.clone())
            .or_default();
        *peak = (*peak).max(in_conversation);
        let attempt = state.attempts.entry(url.to_string()).or_default();
        *attempt += 1;
        let attempt = *attempt;
        state.starts.push((Instant::now(), url.to_string()));

        (
            attempt,
            InFlight {
                server: self,
                conversation,
            },
        )
    }

    fn respond(&self, url: &str, attempt: usize, if_none_match: Option<&str>) -> Reply {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let reply = match self.routes.lock().unwrap().get(path) {
            Some(replies) => replies[(attempt - 1).min(replies.len() - 1)].clone(),
            None => Reply::Status(404),
        };
        let Reply::Body(body) = reply else {
            return reply;
        };

        if !path.ends_with('/') {
            let mut state = self.state.lock().unwrap();
            if if_none_match == Some(etag(&body).as_str()) {
                state.not_modified += 1;
                return Reply::Status(304);
            }
            state.bodies_sent += 1;
            return Reply::Body(body);
        }

        // Homeserver listings are sorted and resume after the cursor
        let mut limit = 100;
        let mut cursor = None;
        for (key, value) in query.split('&').filter_map(|pair| pair.split_once('=')) {
            match key {
                "limit" => limit = value.parse().unwrap(),
                "cursor" if !self.ignores_cursor => cursor = Some(percent_decode(value)),
                _ => {}
            }
        }
        let mut entries: Vec<&str> = body.lines().collect();
        entries.sort();
        let page: Vec<&str> = entries
            .into_iter()
            .filter(|entry| cursor.as_deref().map_or(true, |c| *entry > c))
            .take(limit)
            .collect();
        Reply::Body(page.join("\n"))
    }
}

impl Transport for FakeServer {
    fn metrics(&self) -> &RequestMetrics {
        &self.metrics
    }

    fn put<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(async move {
            let (attempt, _in_flight) = self.begin(url);
            self.metrics.sent(RequestKind::Put, body.len());
            self.state
                .lock()
                .unwrap()
                .put_bodies
                .push((url.to_string(), body.to_vec()));
            tokio::time::sleep(self.delays.get(url).copied().unwrap_or(self.latency)).await;
            let reply = self
                .put_routes
                .lock()
                .unwrap()
                .get(url)
                .map(|replies| replies[(attempt - 1).min(replies.len() - 1)].clone())
                .unwrap_or(Reply::Status(200));
            let (status, retry_after, lose_reply) = match reply {
                Reply::Status(status) => (status, None, false),
                Reply::RateLimited { retry_after_secs } => {
                    (429, Some(Duration::from_secs(retry_after_secs)), false)
                }
                Reply::Hang => return futures::future::pending().await,
                Reply::Broken => return Err("connection reset".to_string()),
                Reply::StoredThenBroken => (200, None, true),
                Reply::Body(_) => panic!("a put response cannot serve a body"),
            };
            if (200..300).contains(&status) {
                self.reply(
                    url,
                    vec![Reply::Body(String::from_utf8(body.to_vec()).unwrap())],
                );
                let directory = &url[..url.rfind('/').unwrap() + 1];
                let mut entries = self.entries(directory);
                if !entries.iter().any(|entry| entry == url) {
                    entries.push(url.to_string());
                }
                self.reply(directory, vec![Reply::Body(entries.join("\n"))]);
            }
            if lose_reply {
                return Err("response lost after storage".to_string());
            }
            Ok(HttpResponse {
                status,
                authentication_failure: false,
                retry_after,
                etag: None,
                body: String::new(),
            })
        })
    }

    fn get<'a>(
        &'a self,
        url: &'a str,
        if_none_match: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(async move {
            let (attempt, _in_flight) = self.begin(url);
            let path = url.split('?').next().unwrap();
            let kind = if path.ends_with('/') {
                RequestKind::List
            } else {
                RequestKind::Get
            };
            self.metrics.sent(kind, 0);
            tokio::time::sleep(self.delays.get(path).copied().unwrap_or(self.latency)).await;

            let reply = self.respond(url, attempt, if_none_match);
            let after = {
                let mut after = self.after.lock().unwrap();
                match after.as_ref() {
                    Some((trigger, _)) if trigger == url => after.take(),
                    _ => None,
                }
            };
            if let Some((_, action)) = after {
                action(self);
            }

            let response = |status, retry_after, etag, body| HttpResponse {
                status,
                authentication_failure: false,
                retry_after,
                etag,
                body,
            };
            match reply {
                Reply::Body(body) => {
                    self.metrics.received(kind, body.len());
                    Ok(response(200, None, Some(etag(&body)), body))
                }
                Reply::Status(status) => Ok(response(status, None, None, String::new())),
                Reply::RateLimited { retry_after_secs } => Ok(response(
                    429,
                    Some(Duration::from_secs(retry_after_secs)),
                    None,
                    String::new(),
                )),
                Reply::Hang => futures::future::pending().await,
                Reply::Broken | Reply::StoredThenBroken => Err("connection reset".to_string()),
            }
        })
    }

    fn delete<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(async move {
            let (attempt, _in_flight) = self.begin(url);
            self.metrics.sent(RequestKind::Delete, 0);
            tokio::time::sleep(self.delays.get(url).copied().unwrap_or(self.latency)).await;
            let reply = self
                .delete_routes
                .lock()
                .unwrap()
                .get(url)
                .map(|replies| replies[(attempt - 1).min(replies.len() - 1)].clone());
            let (status, retry_after) = match reply {
                Some(Reply::Status(status)) => (status, None),
                Some(Reply::RateLimited { retry_after_secs }) => {
                    (429, Some(Duration::from_secs(retry_after_secs)))
                }
                Some(Reply::Hang) => return futures::future::pending().await,
                Some(Reply::Broken | Reply::StoredThenBroken) => {
                    return Err("connection reset".to_string())
                }
                Some(Reply::Body(_)) => panic!("a delete response cannot serve a body"),
                None if self.routes.lock().unwrap().contains_key(url) => (200, None),
                None => (404, None),
            };
            if (200..300).contains(&status) {
                self.remove(url);
                self.state.lock().unwrap().deleted.push(url.to_string());
            }
            Ok(HttpResponse {
                status,
                authentication_failure: false,
                retry_after,
                etag: None,
                body: String::new(),
            })
        })
    }
}

fn etag(body: &str) -> String {
    format!("\"{}\"", blake3::hash(body.as_bytes()).to_hex())
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            decoded.push(u8::from_str_radix(&value[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).unwrap()
}

pub fn directory(owner: &Keypair, other: &PublicKey) -> String {
    let path = ConversationKey::derive(owner, other).unwrap().path();
    format!("pubky://{}{}", owner.public_key(), path)
}

/// Entries a hostile homeserver could list in `owner`'s copy of the conversation that do not
/// name a file in it
pub fn entries_outside(owner: &Keypair, other: &PublicKey) -> Vec<String> {
    let listed = directory(owner, other);
    let owner_key = owner.public_key().to_string();
    let path = &listed[format!("pubky://{}", owner_key).len()..];
    vec![
        "http://127.0.0.1:9/probe".to_string(),
        "https://example.com/0000.json".to_string(),
        format!("pubky://{}@127.0.0.1:9{}0000.json", owner_key, path),
        format!("pubky://{}/pub/pubky.app/profile.json", owner_key),
        // The other participant's copy, and another conversation of the owner's
        format!("pubky://{}{}0000.json", other, path),
        format!("{}0000.json", directory(owner, &keypair(99).public_key())),
        listed.clone(),
        format!("{}.", listed),
        format!("{}..", listed),
        format!("{}../../pubky.app/profile.json", listed),
        format!("{}%2e%2e/%2e%2e/profile.json", listed),
        format!("{}..\\..\\profile.json", listed),
        format!("{}nested/0000.json", listed),
        format!("{}0000.json?probe", listed),
        format!("{}0000.json#probe", listed),
    ]
}

pub fn keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(&[seed; 32])
}
