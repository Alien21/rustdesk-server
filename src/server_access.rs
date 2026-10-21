use crate::{
    access_transport::{self, AccessStream},
    common,
};
use async_trait::async_trait;
use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    bytes::{Bytes, BytesMut},
    message_proto::IdPk,
    protobuf::Message as _,
    rendezvous_proto::RelayResponse,
    sodiumoxide::{
        crypto::{hash::sha256, secretbox, sign},
        randombytes,
        utils::memcmp,
    },
    tcp::FramedStream,
    tokio::{
        self,
        sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore},
        time::{timeout, Duration},
    },
    ResultType,
};
use once_cell::sync::OnceCell;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_DEVICES: usize = 4096;
const MAX_SESSIONS: usize = 4096;
const MAX_WAITING: usize = 512;
const AUTH_DOMAIN: &[u8] = b"rustdesk-access-auth-v1\0";
const RELAY_DOMAIN: &[u8] = b"rustdesk-access-relay-v1\0";

pub type DeviceLookup =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> + Send + Sync>;
static CONTROL: OnceCell<Arc<ControlServer>> = OnceCell::new();
static RELAY: OnceCell<Arc<ProtectedRelay>> = OnceCell::new();

pub fn enabled() -> bool {
    !common::get_arg("access-key").is_empty()
}
pub fn is_invitation_id(id: &str) -> bool {
    id.len() == 11 && id.starts_with("P-") && id[2..].bytes().all(|b| b.is_ascii_digit())
}
fn now() -> ResultType<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(value: &'a Value, key: &str) -> ResultType<&'a str> {
    value[key].as_str().ok_or_else(|| anyhow!("missing {key}"))
}
fn verify_proof(
    pk: &[u8],
    signature: &str,
    domain: &[u8],
    binding: &[u8],
    first: &[u8],
    last: &[u8],
) -> ResultType<()> {
    let pk = sign::PublicKey::from_slice(pk).context("invalid device public key")?;
    let signature = sign::Signature::from_bytes(&access_transport::decode(signature)?)
        .map_err(|_| anyhow!("invalid device signature"))?;
    let mut payload = Vec::from(domain);
    payload.extend_from_slice(binding);
    payload.extend_from_slice(first);
    payload.push(0);
    payload.extend_from_slice(last);
    if !sign::verify_detached(&signature, &payload, &pk) {
        bail!("invalid device proof");
    }
    Ok(())
}

#[derive(Clone)]
struct Identity {
    id: String,
    key: Vec<u8>,
    addr: SocketAddr,
}
struct Device {
    identity: Identity,
    tx: mpsc::Sender<Value>,
    generation: String,
}
#[derive(Clone)]
struct Invitation {
    owner: String,
    expires_at: u64,
}
#[derive(Clone, serde_derive::Serialize, serde_derive::Deserialize)]
struct Grant {
    uuid: String,
    id: String,
    owner: String,
    host_key: Vec<u8>,
    controller_key: Vec<u8>,
    guest: bool,
    expires_at: u64,
}
#[derive(Default)]
struct State {
    devices: HashMap<String, Device>,
    invitations: HashMap<String, Invitation>,
    sessions: HashMap<String, Grant>,
    attempts: AttemptLimiter,
}
impl State {
    fn online_ids(&self) -> HashSet<String> {
        self.devices
            .iter()
            .filter(|(_, device)| !device.tx.is_closed())
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn prune(&mut self, time: u64) {
        self.invitations
            .retain(|_, invitation| invitation.expires_at > time);
        self.sessions.retain(|_, grant| grant.expires_at > time);
        self.attempts.prune(time);
    }
    fn allow_attempt(&mut self, ip: IpAddr, time: u64) -> bool {
        self.prune(time);
        self.attempts.allow(ip, time)
    }
    fn valid_invitation(&self, owner: &str, id: &str, uuid: &str, time: u64) -> bool {
        let Some(invitation) = self.invitations.get(id) else {
            return false;
        };
        let Some(session) = self.sessions.get(uuid) else {
            return false;
        };
        invitation.owner == owner
            && invitation.expires_at > time
            && session.owner == owner
            && session.id == id
            && session.guest
            && session.expires_at > time
    }
}

#[derive(Default)]
struct AttemptLimiter(HashMap<IpAddr, (u64, u32)>);
impl AttemptLimiter {
    fn prune(&mut self, time: u64) {
        self.0.retain(|_, (start, _)| time.saturating_sub(*start) < 60);
    }
    fn allow(&mut self, ip: IpAddr, time: u64) -> bool {
        self.prune(time);
        if self.0.len() >= MAX_DEVICES && !self.0.contains_key(&ip) {
            return false;
        }
        let attempt = self.0.entry(ip).or_insert((time, 0));
        attempt.1 = attempt.1.saturating_add(1);
        attempt.1 <= 120
    }
}

struct ControlServer {
    state: Mutex<State>,
    sk: sign::SecretKey,
    access_key: String,
    relay_server: String,
    lookup: DeviceLookup,
    handshakes: Arc<Semaphore>,
    prefaces: Arc<Semaphore>,
}

fn ticket_key(secret: &str) -> secretbox::Key {
    let mut bytes = Vec::from(b"rustdesk-access-ticket-v1\0".as_slice());
    bytes.extend_from_slice(secret.as_bytes());
    secretbox::Key(sha256::hash(&bytes).0)
}
fn issue_ticket(grant: &Grant, secret: &str) -> ResultType<String> {
    let nonce = secretbox::gen_nonce();
    let mut bytes = nonce.0.to_vec();
    bytes.extend_from_slice(&secretbox::seal(
        &serde_json::to_vec(grant)?,
        &nonce,
        &ticket_key(secret),
    ));
    Ok(access_transport::encode(&bytes))
}
fn open_ticket(ticket: &str, secret: &str) -> ResultType<Grant> {
    if ticket.len() > 4096 {
        bail!("relay ticket too large");
    }
    let bytes = access_transport::decode(ticket)?;
    if bytes.len() <= secretbox::NONCEBYTES {
        bail!("invalid relay ticket");
    }
    let nonce = secretbox::Nonce::from_slice(&bytes[..secretbox::NONCEBYTES])
        .context("invalid relay nonce")?;
    let plain = secretbox::open(&bytes[secretbox::NONCEBYTES..], &nonce, &ticket_key(secret))
        .map_err(|_| anyhow!("invalid relay ticket"))?;
    let grant: Grant = serde_json::from_slice(&plain)?;
    if grant.uuid.is_empty() || grant.expires_at <= now()? {
        bail!("relay ticket expired");
    }
    Ok(grant)
}

pub fn init_control(
    sk: sign::SecretKey,
    relay_server: String,
    lookup: DeviceLookup,
) -> ResultType<()> {
    let access_key = common::get_arg("access-key");
    if access_key.is_empty() {
        return Ok(());
    }
    CONTROL
        .set(Arc::new(ControlServer {
            state: Mutex::new(State::default()),
            sk,
            access_key,
            relay_server,
            lookup,
            handshakes: Arc::new(Semaphore::new(128)),
            prefaces: Arc::new(Semaphore::new(128)),
        }))
        .map_err(|_| anyhow!("private control already initialized"))?;
    Ok(())
}

fn pack_online_states(peers: &[String], online: &HashSet<String>) -> BytesMut {
    let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
    for (i, id) in peers.iter().enumerate() {
        if online.contains(id) {
            states[i / 8] |= 1 << (7 - i % 8);
        }
    }
    states
}

pub async fn online_states(peers: &[String]) -> ResultType<BytesMut> {
    let control = CONTROL.get().context("private control is not ready")?;
    let online = control.state.lock().await.online_ids();
    Ok(pack_online_states(peers, &online))
}

// Bound the first shared TCP frame before parsing or running cryptography.
pub fn control_preamble() -> ResultType<OwnedSemaphorePermit> {
    CONTROL
        .get()
        .context("private control is not ready")?
        .prefaces
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("too many private control preambles"))
}

// The ordinary hbbs TCP dispatcher has already consumed the exact upgrade frame.
pub async fn control_connection(stream: FramedStream, addr: SocketAddr) -> ResultType<()> {
    CONTROL
        .get()
        .context("private control is not ready")?
        .clone()
        .handle(stream, addr)
        .await
}

impl ControlServer {
    async fn authenticate(
        &self,
        stream: &mut AccessStream,
        addr: SocketAddr,
    ) -> ResultType<Identity> {
        let auth: Value = access_transport::recv_json(stream).await?;
        let offered = text(&auth, "access_key")?;
        if text(&auth, "op")? != "auth" || !memcmp(offered.as_bytes(), self.access_key.as_bytes()) {
            bail!("private server authentication failed");
        }
        let id = text(&auth, "id")?;
        if id.is_empty() || id.len() > 253 || id.starts_with("P-") {
            bail!("invalid private device ID");
        }
        let key = access_transport::decode(text(&auth, "device_key")?)?;
        verify_proof(
            &key,
            text(&auth, "signature")?,
            AUTH_DOMAIN,
            &stream.binding(),
            id.as_bytes(),
            &key,
        )?;
        access_transport::send_json(stream, &json!({"op":"ok"})).await?;
        Ok(Identity {
            id: id.to_owned(),
            key,
            addr,
        })
    }

    async fn handle(self: Arc<Self>, socket: FramedStream, addr: SocketAddr) -> ResultType<()> {
        let permit = self.handshakes.clone().try_acquire_owned()
            .map_err(|_| anyhow!("too many private control handshakes"))?;
        if !self.state.lock().await.allow_attempt(addr.ip(), now()?) {
            bail!("too many private server requests");
        }
        let mut stream = timeout(
            Duration::from_secs(10),
            access_transport::accept_framed(socket, &self.sk),
        )
        .await??;
        let identity = timeout(
            Duration::from_secs(10),
            self.authenticate(&mut stream, addr),
        )
        .await??;
        let request: Value = timeout(
            Duration::from_secs(10),
            access_transport::recv_json(&mut stream),
        )
        .await??;
        // Persistent host control channels do not occupy unauthenticated slots.
        drop(permit);
        if request["op"] == "register" {
            return self.register(stream, identity).await;
        }
        let result = self
            .rpc(&identity, request)
            .await
            .unwrap_or_else(|err| json!({"op":"error","error":err.to_string()}));
        access_transport::send_json(&mut stream, &result).await
    }

    async fn register(
        self: Arc<Self>,
        mut stream: AccessStream,
        identity: Identity,
    ) -> ResultType<()> {
        if let Some(existing_key) = (self.lookup)(identity.id.clone()).await {
            if !existing_key.is_empty() && !memcmp(&existing_key, &identity.key) {
                bail!("device ID already belongs to another key");
            }
        }
        let (tx, mut rx) = mpsc::channel(32);
        let generation = uuid::Uuid::new_v4().to_string();
        {
            let mut state = self.state.lock().await;
            if let Some(existing) = state.devices.get(&identity.id) {
                if !memcmp(&existing.identity.key, &identity.key) {
                    bail!("device ID already registered");
                }
            }
            if state.devices.len() >= MAX_DEVICES && !state.devices.contains_key(&identity.id) {
                bail!("private server device limit reached");
            }
            state
                .invitations
                .retain(|_, invitation| invitation.owner != identity.id);
            state.sessions.retain(|_, grant| grant.owner != identity.id);
            state.devices.insert(
                identity.id.clone(),
                Device {
                    identity: identity.clone(),
                    tx: tx.clone(),
                    generation: generation.clone(),
                },
            );
        }
        access_transport::send_json(&mut stream, &json!({"op":"registered","keep_alive":15}))
            .await?;
        let (mut read, mut write) = tokio::io::split(stream);
        let reader = async {
            loop {
                let request: Value = timeout(
                    Duration::from_secs(60),
                    access_transport::recv_json(&mut read),
                )
                .await??;
                if request["op"] != "ping" {
                    bail!("invalid host control request");
                }
                tx.send(json!({"op":"pong"}))
                    .await
                    .map_err(|_| anyhow!("host control closed"))?;
            }
            #[allow(unreachable_code)]
            Ok::<(), hbb_common::anyhow::Error>(())
        };
        let writer = async {
            while let Some(response) = rx.recv().await {
                access_transport::send_json(&mut write, &response).await?;
            }
            Ok::<(), hbb_common::anyhow::Error>(())
        };
        tokio::select! { _ = reader => {}, _ = writer => {} }
        let mut state = self.state.lock().await;
        if state
            .devices
            .get(&identity.id)
            .map(|d| d.generation.as_str())
            == Some(generation.as_str())
        {
            state.devices.remove(&identity.id);
            state
                .invitations
                .retain(|_, invitation| invitation.owner != identity.id);
            state.sessions.retain(|_, grant| grant.owner != identity.id);
        }
        Ok(())
    }

    async fn rpc(&self, identity: &Identity, request: Value) -> ResultType<Value> {
        let time = now()?;
        self.state.lock().await.prune(time);
        match text(&request, "op")? {
            "create_invitation" => {
                let minutes = request["minutes"]
                    .as_u64()
                    .context("missing invitation validity")?;
                if !(1..=1440).contains(&minutes) {
                    bail!("invitation validity must be 1 to 1440 minutes");
                }
                {
                    let state = self.state.lock().await;
                    let host = state
                        .devices
                        .get(&identity.id)
                        .context("device is not registered")?;
                    if !memcmp(&host.identity.key, &identity.key) {
                        bail!("device identity mismatch");
                    }
                }
                for _ in 0..128 {
                    let id = format!(
                        "P-{}",
                        100_000_000 + randombytes::randombytes_uniform(900_000_000)
                    );
                    if (self.lookup)(id.clone()).await.is_some() {
                        continue;
                    }
                    let mut state = self.state.lock().await;
                    if state.invitations.contains_key(&id) {
                        continue;
                    }
                    state
                        .invitations
                        .retain(|_, invite| invite.owner != identity.id);
                    let expires_at = time + minutes * 60;
                    state.invitations.insert(
                        id.clone(),
                        Invitation {
                            owner: identity.id.clone(),
                            expires_at,
                        },
                    );
                    return Ok(json!({"op":"invitation","id":id,"expires_at":expires_at}));
                }
                bail!("could not allocate invitation ID");
            }
            "invitation_status" => {
                let state = self.state.lock().await;
                self.check_host(&state, identity)?;
                let invitation = state
                    .invitations
                    .iter()
                    .find(|(_, invite)| invite.owner == identity.id);
                Ok(match invitation {
                    Some((id, invite)) => {
                        json!({"op":"invitation","id":id,"expires_at":invite.expires_at})
                    }
                    None => json!({"op":"invitation","id":"","expires_at":0}),
                })
            }
            "revoke_invitation" => {
                let id = request["id"].as_str().unwrap_or("");
                let mut state = self.state.lock().await;
                self.check_host(&state, identity)?;
                state.invitations.retain(|alias, invite| {
                    invite.owner != identity.id || (!id.is_empty() && alias != id)
                });
                Ok(json!({"op":"ok"}))
            }
            "validate_invitation" => {
                let state = self.state.lock().await;
                self.check_host(&state, identity)?;
                let valid = state.valid_invitation(
                    &identity.id,
                    text(&request, "id")?,
                    text(&request, "uuid")?,
                    time,
                );
                Ok(json!({"op":"valid","valid":valid}))
            }
            "connect" => {
                let id = text(&request, "id")?;
                if id.starts_with("P-") {
                    bail!("invitation uses the public connection protocol");
                }
                let (session, _) = self.new_session(id, Some(identity), identity.addr).await?;
                Ok(session)
            }
            _ => bail!("unsupported private server request"),
        }
    }

    fn check_host(&self, state: &State, identity: &Identity) -> ResultType<()> {
        let host = state
            .devices
            .get(&identity.id)
            .context("device is not registered")?;
        if !memcmp(&host.identity.key, &identity.key) {
            bail!("device identity mismatch");
        }
        Ok(())
    }

    async fn new_session(
        &self,
        id: &str,
        controller: Option<&Identity>,
        peer_addr: SocketAddr,
    ) -> ResultType<(Value, RelayResponse)> {
        let time = now()?;
        let (grant, host_addr, host_tx) = {
            let mut state = self.state.lock().await;
            state.prune(time);
            if state.sessions.len() >= MAX_SESSIONS {
                bail!("private session limit reached");
            }
            let (owner, expires_at) = if controller.is_none() {
                let invite = state
                    .invitations
                    .get(id)
                    .context("invitation expired or does not exist")?;
                (invite.owner.clone(), invite.expires_at)
            } else {
                (id.to_owned(), time + 60)
            };
            let host = state
                .devices
                .get(&owner)
                .context("target device is offline")?;
            let grant = Grant {
                uuid: uuid::Uuid::new_v4().to_string(),
                id: id.to_owned(),
                owner,
                host_key: host.identity.key.clone(),
                controller_key: controller.map(|c| c.key.clone()).unwrap_or_default(),
                guest: controller.is_none(),
                expires_at,
            };
            let result = (grant.clone(), host.identity.addr, host.tx.clone());
            state.sessions.insert(grant.uuid.clone(), grant);
            result
        };
        let ticket = issue_ticket(&grant, &self.access_key)?;
        let certificate = sign::sign(
            &IdPk {
                id: id.to_owned(),
                pk: grant.host_key.clone().into(),
                ..Default::default()
            }
            .write_to_bytes()?,
            &self.sk,
        );
        let host_event = json!({"op":"session","uuid":grant.uuid,"id":id,"expires_at":grant.expires_at,
            "relay_server":self.relay_server,"ticket":ticket,"guest":grant.guest,"peer_addr":peer_addr.to_string()});
        host_tx
            .try_send(host_event)
            .map_err(|_| anyhow!("target device control is busy"))?;
        let response = json!({"op":"session","uuid":grant.uuid,"id":id,"expires_at":grant.expires_at,
            "relay_server":self.relay_server,"ticket":ticket,"guest":grant.guest,"peer_addr":host_addr.to_string(),
            "certificate":access_transport::encode(&certificate)});
        let mut public = RelayResponse {
            uuid: grant.uuid,
            relay_server: self.relay_server.clone(),
            ..Default::default()
        };
        public.set_pk(certificate.into());
        Ok((response, public))
    }
}

pub async fn guest_session(id: &str, addr: SocketAddr) -> ResultType<RelayResponse> {
    if !is_invitation_id(id) {
        bail!("private server requires an invitation");
    }
    let control = CONTROL.get().context("private server is not ready")?;
    {
        let mut state = control.state.lock().await;
        if !state.allow_attempt(addr.ip(), now()?) {
            bail!("too many invitation connection attempts");
        }
    }
    Ok(control.new_session(id, None, addr).await?.1)
}

#[async_trait]
pub trait RelayEndpoint: Send + Sync {
    fn remote_addr(&self) -> SocketAddr;
    async fn receive(&mut self) -> ResultType<Option<BytesMut>>;
    async fn transmit(&mut self, bytes: Bytes) -> ResultType<()>;
}
struct OwnedEndpoint(FramedStream);
#[async_trait]
impl RelayEndpoint for OwnedEndpoint {
    fn remote_addr(&self) -> SocketAddr {
        self.0 .1
    }
    async fn receive(&mut self) -> ResultType<Option<BytesMut>> {
        Ok(self.0.next().await.transpose()?)
    }
    async fn transmit(&mut self, bytes: Bytes) -> ResultType<()> {
        self.0.send_bytes(bytes).await
    }
}
struct Waiting {
    generation: String,
    ticket: Option<String>,
    grant: Option<Grant>,
    host: Option<Box<dyn RelayEndpoint>>,
    controller: Option<Box<dyn RelayEndpoint>>,
    guest: Option<Box<dyn RelayEndpoint>>,
    guest_id: Option<String>,
}
pub type RelayPump = Arc<
    dyn Fn(
            SocketAddr,
            Box<dyn RelayEndpoint>,
            Box<dyn RelayEndpoint>,
        ) -> Pin<Box<dyn Future<Output = ResultType<()>> + Send>>
        + Send
        + Sync,
>;
struct ProtectedRelay {
    secret: String,
    waiting: Mutex<HashMap<String, Waiting>>,
    pump: RelayPump,
    sk: sign::SecretKey,
    handshakes: Arc<Semaphore>,
    prefaces: Arc<Semaphore>,
    attempts: Mutex<AttemptLimiter>,
}

pub fn init_relay(sk: sign::SecretKey, pump: RelayPump) -> ResultType<()> {
    let secret = common::get_arg("access-key");
    if secret.is_empty() {
        return Ok(());
    }
    RELAY
        .set(Arc::new(ProtectedRelay {
            secret,
            waiting: Mutex::new(HashMap::new()),
            pump,
            sk,
            handshakes: Arc::new(Semaphore::new(128)),
            prefaces: Arc::new(Semaphore::new(128)),
            attempts: Mutex::new(AttemptLimiter::default()),
        }))
        .map_err(|_| anyhow!("protected relay already initialized"))?;
    Ok(())
}

pub fn relay_preamble() -> ResultType<OwnedSemaphorePermit> {
    RELAY
        .get()
        .context("protected relay is not ready")?
        .prefaces
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("too many protected relay preambles"))
}

// The ordinary hbbr TCP dispatcher applies BLOCKLIST before this upgrade.
pub async fn relay_connection(stream: FramedStream, addr: SocketAddr) -> ResultType<()> {
    RELAY
        .get()
        .context("protected relay is not ready")?
        .clone()
        .own_connection(stream, addr)
        .await
}

impl ProtectedRelay {
    async fn own_connection(
        self: Arc<Self>,
        socket: FramedStream,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let permit = self.handshakes.clone().try_acquire_owned()
            .map_err(|_| anyhow!("too many protected relay handshakes"))?;
        if !self.attempts.lock().await.allow(addr.ip(), now()?) {
            bail!("too many protected relay requests");
        }
        let mut stream = timeout(
            Duration::from_secs(10),
            access_transport::accept_framed(socket, &self.sk),
        )
        .await??;
        let request: Value = timeout(
            Duration::from_secs(10),
            access_transport::recv_json(&mut stream),
        )
        .await??;
        if text(&request, "op")? != "relay"
            || !memcmp(
                text(&request, "access_key")?.as_bytes(),
                self.secret.as_bytes(),
            )
        {
            bail!("protected relay authentication failed");
        }
        let ticket = text(&request, "ticket")?.to_owned();
        let grant = open_ticket(&ticket, &self.secret)?;
        let role = text(&request, "role")?;
        let key = match role {
            "host" => &grant.host_key,
            "controller" if !grant.guest => &grant.controller_key,
            _ => bail!("invalid relay role"),
        };
        verify_proof(
            key,
            text(&request, "signature")?,
            RELAY_DOMAIN,
            &stream.binding(),
            role.as_bytes(),
            ticket.as_bytes(),
        )?;
        access_transport::send_json(&mut stream, &json!({"op":"ok"})).await?;
        // Waiting pairs are bounded separately; active sessions release handshake slots.
        drop(permit);
        let endpoint = Box::new(OwnedEndpoint(FramedStream::from(stream, addr)));
        self.add(
            grant.uuid.clone(),
            Some((ticket, grant)),
            role,
            None,
            endpoint,
        )
        .await
    }

    async fn add(
        self: &Arc<Self>,
        uuid: String,
        authorization: Option<(String, Grant)>,
        role: &str,
        guest_id: Option<String>,
        endpoint: Box<dyn RelayEndpoint>,
    ) -> ResultType<()> {
        let generation = uuid::Uuid::new_v4().to_string();
        let pair = {
            let mut waiting = self.waiting.lock().await;
            if waiting.len() >= MAX_WAITING && !waiting.contains_key(&uuid) {
                bail!("protected relay pending limit reached");
            }
            if role == "guest"
                && !waiting.contains_key(&uuid)
                && waiting
                    .values()
                    .filter(|entry| entry.grant.is_none())
                    .count()
                    >= MAX_WAITING / 4
            {
                bail!("anonymous relay pending limit reached");
            }
            if role == "guest"
                && !waiting.contains_key(&uuid)
                && waiting
                    .values()
                    .filter(|entry| {
                        entry.grant.is_none()
                            && entry
                                .guest
                                .as_ref()
                                .map(|peer| peer.remote_addr().ip() == endpoint.remote_addr().ip())
                                .unwrap_or(false)
                    })
                    .count()
                    >= 8
            {
                bail!("too many pending invitation relays from this address");
            }
            let entry = waiting.entry(uuid.clone()).or_insert_with(|| Waiting {
                generation: generation.clone(),
                ticket: None,
                grant: None,
                host: None,
                controller: None,
                guest: None,
                guest_id: None,
            });
            if let Some((ticket, grant)) = authorization {
                if let Some(existing) = &entry.ticket {
                    if existing != &ticket {
                        bail!("relay grant mismatch");
                    }
                }
                if entry
                    .guest_id
                    .as_ref()
                    .map(|id| !grant.guest || id != &grant.id)
                    .unwrap_or(false)
                {
                    entry.guest = None;
                    entry.guest_id = None;
                }
                entry.ticket = Some(ticket);
                entry.grant = Some(grant);
            }
            match role {
                "host" if entry.host.is_none() => entry.host = Some(endpoint),
                "controller" if entry.controller.is_none() => entry.controller = Some(endpoint),
                "guest" if entry.guest.is_none() => {
                    if let Some(grant) = &entry.grant {
                        if !grant.guest || guest_id.as_deref() != Some(grant.id.as_str()) {
                            bail!("anonymous relay does not match an invitation");
                        }
                    }
                    entry.guest_id = guest_id;
                    entry.guest = Some(endpoint);
                }
                _ => bail!("relay role already occupied"),
            }
            let ready = entry
                .grant
                .as_ref()
                .map(|g| {
                    entry.host.is_some()
                        && if g.guest {
                            entry.guest.is_some()
                        } else {
                            entry.controller.is_some()
                        }
                })
                .unwrap_or(false);
            if ready {
                let mut entry = waiting.remove(&uuid).context("relay pairing disappeared")?;
                let grant = entry
                    .grant
                    .as_ref()
                    .context("relay authorization missing")?;
                if grant.expires_at <= now()? {
                    bail!("relay admission expired");
                }
                let host = entry.host.take().context("relay host missing")?;
                let peer = if grant.guest {
                    entry.guest.take()
                } else {
                    entry.controller.take()
                }
                .context("relay peer missing")?;
                Some((host, peer))
            } else {
                None
            }
        };
        if let Some((host, peer)) = pair {
            (self.pump)(peer.remote_addr(), host, peer).await?;
        } else {
            let relay = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let mut waiting = relay.waiting.lock().await;
                if waiting.get(&uuid).map(|e| e.generation.as_str()) == Some(generation.as_str()) {
                    waiting.remove(&uuid);
                }
            });
        }
        Ok(())
    }
}

pub async fn public_relay(
    uuid: String,
    id: String,
    endpoint: Box<dyn RelayEndpoint>,
) -> ResultType<()> {
    if !is_invitation_id(&id) {
        bail!("anonymous relay requires an invitation ID");
    }
    if uuid.len() != 36 || uuid::Uuid::parse_str(&uuid).is_err() {
        bail!("invalid relay session");
    }
    let relay = RELAY.get().context("protected relay is not ready")?;
    relay.add(uuid, None, "guest", Some(id), endpoint).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_online_states_preserve_request_order_across_bytes() {
        let mut state = State::default();
        let mut receivers = Vec::new();
        for id in ["alpha", "beta"] {
            let (tx, rx) = mpsc::channel(1);
            receivers.push(rx);
            state.devices.insert(id.into(), Device {
                identity: Identity {
                    id: id.into(),
                    key: Vec::new(),
                    addr: "127.0.0.1:12345".parse().unwrap(),
                },
                tx,
                generation: String::new(),
            });
        }
        let peers = ["alpha", "unknown", "beta", "alpha", "", "unknown", "beta", "", "beta", "alpha"]
            .map(str::to_owned);
        let online = state.online_ids();
        assert_eq!(&pack_online_states(&peers, &online)[..], &[0xb2, 0xc0]);
        assert!(pack_online_states(&[], &online).is_empty());
    }

    #[test]
    fn private_online_states_exclude_closed_removed_and_invitation_entries() {
        let mut state = State::default();
        let (tx, rx) = mpsc::channel(1);
        state.devices.insert("device".into(), Device {
            identity: Identity {
                id: "device".into(),
                key: Vec::new(),
                addr: "127.0.0.1:12345".parse().unwrap(),
            },
            tx,
            generation: String::new(),
        });
        state.invitations.insert("P-123456789".into(), Invitation {
            owner: "device".into(),
            expires_at: u64::MAX,
        });
        let peers = ["device", "unknown", "P-123456789"].map(str::to_owned);
        assert_eq!(&pack_online_states(&peers, &state.online_ids())[..], &[0x80]);
        drop(rx);
        assert_eq!(&pack_online_states(&peers, &state.online_ids())[..], &[0]);
        let (tx, _rx) = mpsc::channel(1);
        state.devices.get_mut("device").unwrap().tx = tx;
        assert_eq!(&pack_online_states(&peers, &state.online_ids())[..], &[0x80]);
        state.devices.remove("device");
        assert_eq!(&pack_online_states(&peers, &state.online_ids())[..], &[0]);
    }

    #[test]
    fn private_attempts_are_limited_per_address_and_expire() {
        let ip = "192.0.2.1".parse().unwrap();
        let other = "192.0.2.2".parse().unwrap();
        let mut attempts = AttemptLimiter::default();
        for _ in 0..120 {
            assert!(attempts.allow(ip, 100));
        }
        assert!(!attempts.allow(ip, 100));
        assert!(attempts.allow(other, 100));
        assert!(!attempts.allow(ip, 159));
        assert!(attempts.allow(ip, 160));
    }

    #[test]
    fn private_attempts_bound_distinct_addresses_before_authentication() {
        let mut attempts = AttemptLimiter(
            (0..MAX_DEVICES as u32)
                .map(|ip| (IpAddr::V4(std::net::Ipv4Addr::from(ip)), (100, 1)))
                .collect(),
        );
        let extra = "192.0.2.1".parse().unwrap();
        assert!(!attempts.allow(extra, 100));
        assert!(attempts.allow("0.0.0.1".parse().unwrap(), 100));
        assert!(attempts.allow(extra, 160));
        assert_eq!(attempts.0.len(), 1);
    }

    #[test]
    fn invitation_validation_requires_live_alias_owner_and_session() {
        let mut state = State::default();
        state.invitations.insert(
            "P-123456789".into(),
            Invitation {
                owner: "owner".into(),
                expires_at: 200,
            },
        );
        state.sessions.insert(
            "session".into(),
            Grant {
                uuid: "session".into(),
                id: "P-123456789".into(),
                owner: "owner".into(),
                host_key: vec![1; 32],
                controller_key: Vec::new(),
                guest: true,
                expires_at: 200,
            },
        );
        assert!(state.valid_invitation("owner", "P-123456789", "session", 199));
        assert!(!state.valid_invitation("owner", "P-123456789", "session", 200));
        assert!(!state.valid_invitation("owner", "P-123456789", "another-session", 100));
        assert!(!state.valid_invitation("other-owner", "P-123456789", "session", 100));
        state.invitations.clear();
        assert!(!state.valid_invitation("owner", "P-123456789", "session", 100));
    }

    #[test]
    fn relay_ticket_is_bound_to_the_configured_private_secret() {
        let grant = Grant {
            uuid: uuid::Uuid::new_v4().to_string(),
            id: "P-123456789".into(),
            owner: "owner".into(),
            host_key: vec![1; 32],
            controller_key: Vec::new(),
            guest: true,
            expires_at: now().unwrap() + 60,
        };
        let ticket = issue_ticket(&grant, "correct-private-secret").unwrap();
        assert_eq!(
            open_ticket(&ticket, "correct-private-secret").unwrap().uuid,
            grant.uuid
        );
        assert!(open_ticket(&ticket, "different-private-secret").is_err());
        let mut corrupted = access_transport::decode(&ticket).unwrap();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 1;
        }
        assert!(open_ticket(
            &access_transport::encode(&corrupted),
            "correct-private-secret"
        )
        .is_err());
    }

    #[test]
    fn invitation_namespace_is_distinct_from_numeric_ids() {
        assert!(is_invitation_id("P-254785236"));
        for id in ["254785236", "P-123", "P-12345678A", "p-123456789"] {
            assert!(!is_invitation_id(id));
        }
    }
    struct QuietEndpoint(SocketAddr);
    #[async_trait]
    impl RelayEndpoint for QuietEndpoint {
        fn remote_addr(&self) -> SocketAddr {
            self.0
        }
        async fn receive(&mut self) -> ResultType<Option<BytesMut>> {
            std::future::pending().await
        }
        async fn transmit(&mut self, _: Bytes) -> ResultType<()> {
            bail!("unexpected relay data");
        }
    }

    fn test_relay() -> (Arc<ProtectedRelay>, Arc<std::sync::atomic::AtomicUsize>) {
        let pairs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = pairs.clone();
        let pump: RelayPump = Arc::new(move |_, _, _| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        });
        (
            Arc::new(ProtectedRelay {
                secret: "test-secret".into(),
                waiting: Mutex::new(HashMap::new()),
                pump,
                sk: sign::gen_keypair().1,
                handshakes: Arc::new(Semaphore::new(128)),
                prefaces: Arc::new(Semaphore::new(128)),
                attempts: Mutex::new(AttemptLimiter::default()),
            }),
            pairs,
        )
    }
    fn endpoint() -> Box<dyn RelayEndpoint> {
        Box::new(QuietEndpoint("127.0.0.1:12345".parse().unwrap()))
    }
    fn guest_grant() -> Grant {
        Grant {
            uuid: uuid::Uuid::new_v4().to_string(),
            id: "P-123456789".into(),
            owner: "owner".into(),
            host_key: vec![1; 32],
            controller_key: Vec::new(),
            guest: true,
            expires_at: now().unwrap() + 60,
        }
    }

    #[tokio::test]
    async fn two_public_halves_cannot_start_relay_until_owned_host_arrives() {
        let (relay, pairs) = test_relay();
        let grant = guest_grant();
        relay
            .add(
                grant.uuid.clone(),
                None,
                "guest",
                Some(grant.id.clone()),
                endpoint(),
            )
            .await
            .unwrap();
        assert!(relay
            .add(
                grant.uuid.clone(),
                None,
                "guest",
                Some(grant.id.clone()),
                endpoint()
            )
            .await
            .is_err());
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 0);
        relay
            .add(
                grant.uuid.clone(),
                Some(("ticket".into(), grant)),
                "host",
                None,
                endpoint(),
            )
            .await
            .unwrap();
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn anonymous_half_cannot_join_private_grant_or_different_invitation() {
        let (relay, pairs) = test_relay();
        let mut grant = guest_grant();
        grant.guest = false;
        grant.id = "owned-device".into();
        grant.controller_key = vec![2; 32];
        relay
            .add(
                grant.uuid.clone(),
                Some(("private-ticket".into(), grant.clone())),
                "host",
                None,
                endpoint(),
            )
            .await
            .unwrap();
        assert!(relay
            .add(
                grant.uuid.clone(),
                None,
                "guest",
                Some("P-123456789".into()),
                endpoint()
            )
            .await
            .is_err());
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 0);
        relay
            .add(
                grant.uuid.clone(),
                Some(("private-ticket".into(), grant)),
                "controller",
                None,
                endpoint(),
            )
            .await
            .unwrap();
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 1);

        let grant = guest_grant();
        relay
            .add(
                grant.uuid.clone(),
                Some(("guest-ticket".into(), grant.clone())),
                "host",
                None,
                endpoint(),
            )
            .await
            .unwrap();
        assert!(relay
            .add(
                grant.uuid.clone(),
                None,
                "guest",
                Some("P-987654321".into()),
                endpoint()
            )
            .await
            .is_err());
        relay
            .add(
                grant.uuid.clone(),
                None,
                "guest",
                Some(grant.id),
                endpoint(),
            )
            .await
            .unwrap();
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expired_grant_never_starts_relay() {
        let (relay, pairs) = test_relay();
        let mut grant = guest_grant();
        grant.expires_at = now().unwrap();
        relay
            .add(
                grant.uuid.clone(),
                Some(("expired-ticket".into(), grant.clone())),
                "host",
                None,
                endpoint(),
            )
            .await
            .unwrap();
        assert!(relay
            .add(grant.uuid, None, "guest", Some(grant.id), endpoint())
            .await
            .is_err());
        assert_eq!(pairs.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    struct ChannelEndpoint {
        input: mpsc::Receiver<BytesMut>,
        output: mpsc::Sender<Bytes>,
    }
    #[async_trait]
    impl RelayEndpoint for ChannelEndpoint {
        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:12345".parse().unwrap()
        }
        async fn receive(&mut self) -> ResultType<Option<BytesMut>> {
            Ok(self.input.recv().await)
        }
        async fn transmit(&mut self, bytes: Bytes) -> ResultType<()> {
            self.output
                .send(bytes)
                .await
                .map_err(|_| anyhow!("test endpoint closed"))
        }
    }

    #[tokio::test]
    async fn established_bridge_still_delivers_data_after_admission_deadline() {
        let (host_input, host_receiver) = mpsc::channel(1);
        let (host_output, _host_observer) = mpsc::channel(1);
        let (_guest_input, guest_receiver) = mpsc::channel(1);
        let (guest_output, mut guest_observer) = mpsc::channel(1);
        let (started, start_receiver) = tokio::sync::oneshot::channel();
        let started = Arc::new(std::sync::Mutex::new(Some(started)));
        let pump: RelayPump = Arc::new(move |_, mut host, mut guest| {
            if let Some(started) = started.lock().unwrap().take() {
                let _ = started.send(());
            }
            Box::pin(async move {
                let bytes = host.receive().await?.context("test host disconnected")?;
                guest.transmit(bytes.into()).await
            })
        });
        let relay = Arc::new(ProtectedRelay {
            secret: "test-secret".into(),
            waiting: Mutex::new(HashMap::new()),
            pump,
            sk: sign::gen_keypair().1,
            handshakes: Arc::new(Semaphore::new(128)),
            prefaces: Arc::new(Semaphore::new(128)),
            attempts: Mutex::new(AttemptLimiter::default()),
        });
        let mut grant = guest_grant();
        grant.expires_at = now().unwrap() + 1;
        relay
            .add(
                grant.uuid.clone(),
                Some(("ticket".into(), grant.clone())),
                "host",
                None,
                Box::new(ChannelEndpoint {
                    input: host_receiver,
                    output: host_output,
                }),
            )
            .await
            .unwrap();
        let peer = tokio::spawn(async move {
            relay
                .add(
                    grant.uuid,
                    None,
                    "guest",
                    Some(grant.id),
                    Box::new(ChannelEndpoint {
                        input: guest_receiver,
                        output: guest_output,
                    }),
                )
                .await
        });
        start_receiver.await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        host_input
            .send(BytesMut::from(&b"session remains connected"[..]))
            .await
            .unwrap();
        let delivered = timeout(Duration::from_secs(2), guest_observer.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.as_ref(), b"session remains connected");
        peer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn guest_response_uses_standard_relay_message_with_signed_alias_identity() {
        let (server_pk, server_sk) = sign::gen_keypair();
        let (device_pk, _) = sign::gen_keypair();
        let (events, mut host_events) = mpsc::channel(1);
        let owner = Identity {
            id: "123456789".into(),
            key: device_pk.0.to_vec(),
            addr: "127.0.0.1:23456".parse().unwrap(),
        };
        let mut state = State::default();
        state.devices.insert(
            owner.id.clone(),
            Device {
                identity: owner.clone(),
                tx: events,
                generation: "generation".into(),
            },
        );
        state.invitations.insert(
            "P-254785236".into(),
            Invitation {
                owner: owner.id,
                expires_at: now().unwrap() + 60,
            },
        );
        let lookup: DeviceLookup = Arc::new(|_| Box::pin(async { None }));
        let server = ControlServer {
            state: Mutex::new(state),
            sk: server_sk,
            access_key: "test-secret".into(),
            relay_server: "rustdesk.example.com:21117".into(),
            lookup,
            handshakes: Arc::new(Semaphore::new(128)),
            prefaces: Arc::new(Semaphore::new(128)),
        };
        let (_, reply) = server
            .new_session("P-254785236", None, "127.0.0.1:34567".parse().unwrap())
            .await
            .unwrap();
        let host_event = host_events.recv().await.unwrap();
        assert_eq!(host_event["uuid"], reply.uuid);
        assert_eq!(host_event["id"], "P-254785236");
        let signed_identity = reply.pk();
        let verified = sign::verify(signed_identity, &server_pk).unwrap();
        let identity = IdPk::parse_from_bytes(&verified).unwrap();
        assert_eq!(identity.id, "P-254785236");
        assert_eq!(identity.pk.as_ref(), device_pk.0);
        assert_eq!(reply.relay_server, "rustdesk.example.com:21117");
        assert!(uuid::Uuid::parse_str(&reply.uuid).is_ok());
    }
}
