use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::PublicKey;
use std::array::TryFromSliceError;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::mail::{MailMessage, Mailbox};

// Maintains the state of connections, both locally and from connected peers.
// The `known_connections` set contains tuples of connections that are gossiped by other peers. For example, anytime a remote peer establishes some new connection,
// it will gossip that connection to other peers.
// The `local_connections` set contains the connections that are established by the local node. For example, when either a new client peer or another router connects to the router.
#[derive(Default)]
pub struct RoutingTable {
    known_connections: HashSet<(PublicKey, PublicKey)>,
    local_connections: HashSet<PublicKey>,
}

impl RoutingTable {
    pub fn find_peer(&self, peer: &PublicKey) -> Vec<PublicKey> {
        let mut r = vec![];
        for (a, b) in &self.known_connections {
            if a == peer {
                r.push(*b);
            } else if b == peer {
                r.push(*a);
            }
        }
        r
    }

    pub fn add_connection(&mut self, a: PublicKey, b: PublicKey) {
        self.known_connections.insert((a, b));
    }

    pub fn add_local_connection(&mut self, peer: PublicKey) {
        self.local_connections.insert(peer);
    }

    pub fn remove_local_connection(&mut self, peer: &PublicKey) {
        self.local_connections.remove(peer);
    }

    pub fn remove_connection(&mut self, a: &PublicKey, b: &PublicKey) {
        self.known_connections.remove(&(*a, *b));
        self.known_connections.remove(&(*b, *a));
    }
}

// Controls the TCP connection lifecycle of all peers. It listens for incoming connections and also connects to other peers.
// Each TCP/peer connection is handled in its own tokio task. Communication with between the connection and the manager happens via channels.
pub struct RouterSocketsManager {
    // The mailbox is used to sign messages and verify signatures.
    // Generally, if this is a router server, the mailbox won't need to sign anything, but it still needs an identity.
    mailbox: Arc<Mailbox>,
    // Aids with lookups for routing messages
    routing_table: Arc<Mutex<RoutingTable>>,
    // A channel shared by all connections to send messages up to the manager. (Each handler gets a clone of it; the manager itself doesn't actually use it)
    to_manager: Arc<UnboundedSender<HandlerToManager>>,
    // The receiving side of the above channel, meant to be used by the manager to listen to messages from all handlers
    from_handler: Arc<Mutex<UnboundedReceiver<HandlerToManager>>>,
    // A mapping from router peers to the channel that sends messages to the handler
    router_peers: Arc<Mutex<HashMap<PublicKey, UnboundedSender<ManagerToHandler>>>>,
    // A mapping from client peers to the channel that sends messages to the handler
    client_peers: Arc<Mutex<HashMap<PublicKey, UnboundedSender<ManagerToHandler>>>>,
}

impl RouterSocketsManager {
    // Create a new manager instance that is identified by the given mailbox
    // Note: Creating the manager doesn't start any network activity. Call `.serve` to start listening for incoming connections.
    pub fn new(mailbox: Mailbox) -> Self {
        let (to_handler, from_handler) = tokio::sync::mpsc::unbounded_channel::<HandlerToManager>();
        Self {
            mailbox: Arc::new(mailbox),
            routing_table: Arc::new(Mutex::new(RoutingTable::default())),
            to_manager: Arc::new(to_handler),
            from_handler: Arc::new(Mutex::new(from_handler)),
            router_peers: Arc::new(Mutex::new(HashMap::new())),
            client_peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Bind the server to the given address and start listening for incoming connections.
    pub async fn serve(&self, addr: SocketAddr) -> Result<(), Error> {
        select! {
            _ = self.background_receiver() => {}
            _ = self.serve_impl(addr) => {}
        }
        Ok(())
    }

    // Initialize an outbound connection to the given address and handle the socket
    pub async fn connect(&self, addr: SocketAddr) -> Result<(), Error> {
        let mut socket = TcpStream::connect(addr).await?;
        let mailbox = self.mailbox.clone();
        let to_manager = self.to_manager.clone();
        tokio::spawn(async move {
            log::info!("Connecting to {}", addr);
            if let Err(e) = handle_connection(to_manager, mailbox, &mut socket).await {
                log::warn!("Connection error: {}", e);
            }
        });
        Ok(())
    }

    // A MailMessage has been received by a handler and must be forwarded accordingly
    async fn message_received(&self, message: MailMessage) -> Result<(), Error> {
        let routing_table = self.routing_table.lock().map_err(|_| Error::Mutex())?;
        if routing_table.local_connections.contains(&message.receiver) {
            self.client_peers
                .lock()?
                .get(&message.receiver)
                .ok_or(Error::Other("Receiver not found".to_owned()))?
                .send(ManagerToHandler::SendMessage(message))
                .map_err(|e| Error::Other(e.to_string()))?;
            return Ok(());
        }
        let candidates = routing_table.find_peer(&message.receiver);
        if candidates.is_empty() {
            self.router_peers
                .lock()
                .map_err(|_| Error::Mutex())?
                .iter()
                .for_each(|(_vk, sender)| {
                    let _ = sender.send(ManagerToHandler::SendMessage(message.clone()));
                });
            return Ok(());
        } else {
            let candidate = candidates[0];
            self.router_peers
                .lock()
                .map_err(|_| Error::Mutex())?
                .get(&candidate)
                .ok_or(Error::Other("No sender found".to_owned()))?
                .send(ManagerToHandler::SendMessage(message))
                .map_err(|e| Error::Other(e.to_string()))?;
            return Ok(());
        }
    }

    // A new router peer has connected to this router
    async fn on_new_router_peer(
        &self,
        vk: PublicKey,
        sender: UnboundedSender<ManagerToHandler>,
    ) -> Result<(), Error> {
        self.router_peers.lock()?.insert(vk, sender);
        Ok(())
    }

    // A new client peer has connected to this router
    async fn on_new_client_peer(
        &self,
        vk: PublicKey,
        sender: UnboundedSender<ManagerToHandler>,
    ) -> Result<(), Error> {
        self.client_peers.lock()?.insert(vk, sender);
        self.routing_table.lock()?.add_local_connection(vk);
        Ok(())
    }

    // A remote peer gossiped a new connection change
    async fn on_remote_peer_change(
        &self,
        notifier: PublicKey,
        change: PeerChange,
    ) -> Result<(), Error> {
        match change {
            PeerChange::AddPublic(vk, _ip, _port) => {
                self.routing_table.lock()?.add_connection(notifier, vk);
            }
            PeerChange::AddPrivate(vk) => {
                self.routing_table.lock()?.add_connection(notifier, vk);
            }
            PeerChange::Remove(vk) => {
                self.routing_table.lock()?.remove_connection(&notifier, &vk);
            }
        }
        Ok(())
    }

    // Process messages sent by the sub-handlers in a never-ending loop
    async fn background_receiver(&self) -> Result<(), Error> {
        while let Some(v) = self
            .from_handler
            .lock()
            .map_err(|_| Error::Mutex())?
            .recv()
            .await
        {
            match v {
                HandlerToManager::MailReceived(message) => self.message_received(message).await?,
                HandlerToManager::NewRouterPeer(vk, sender) => {
                    self.on_new_router_peer(vk, sender).await?
                }
                HandlerToManager::NewClientPeer(vk, sender) => {
                    self.on_new_client_peer(vk, sender).await?
                }
                HandlerToManager::RemotePeerChange(vk, change) => {
                    self.on_remote_peer_change(vk, change).await?
                }
            }
        }
        Ok(())
    }

    // Bind the socket and listen to inbound connections
    async fn serve_impl(&self, addr: SocketAddr) -> Result<(), Error> {
        let listener = TcpListener::bind(addr).await?;
        log::info!("Listening on {}", addr);

        loop {
            let (mut socket, from_addr) = listener.accept().await?;
            log::info!("Rececived connection from {}", from_addr);
            let mailbox = self.mailbox.clone();
            let to_manager = self.to_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(to_manager, mailbox, &mut socket).await {
                    log::warn!("Connection error: {}", e);
                }
            });
        }
    }
}

// Handle a new TCP connection that is not yet known to be valid or what type is on the other end.
async fn handle_connection(
    handler_to_manager: Arc<UnboundedSender<HandlerToManager>>,
    mailbox: Arc<Mailbox>,
    socket: &mut TcpStream,
) -> Result<(), Error> {
    // Authentication
    let vk = authenticate(socket, &mailbox).await?;

    log::info!("Authenticated peer: {}", vk);

    // Read connection type
    let mut conn_type = [0u8; 1];
    socket.write(&[0]).await?;
    socket.read_exact(&mut conn_type).await?;

    match conn_type[0] {
        // Router peer
        0 => {
            log::info!("Router peer connected: {}", vk);
            let (mut read, mut write) = socket.split();
            let (manager_to_handler_sender, mut manager_to_handler_receiver) =
                tokio::sync::mpsc::unbounded_channel::<ManagerToHandler>();
            let handler = RouterHandler {
                vk,
                handler_to_manager: handler_to_manager.clone(),
            };
            handler_to_manager
                .send(HandlerToManager::NewRouterPeer(
                    vk,
                    manager_to_handler_sender,
                ))
                .map_err(|e| Error::Other(e.to_string()))?;
            select! {
                _ = handler.handle_reader(&mut read) => {}
                _ = handler.handle_writer(&mut write, &mut manager_to_handler_receiver) => {}
            }
        }
        // Client peer
        1 => {
            log::info!("Client peer connected: {}", vk);
            let (mut read, mut write) = socket.split();
            let (manager_to_handler_sender, mut manager_to_handler_receiver) =
                tokio::sync::mpsc::unbounded_channel::<ManagerToHandler>();
            let handler = ClientHandler {
                vk,
                handler_to_manager: handler_to_manager.clone(),
            };
            handler_to_manager
                .send(HandlerToManager::NewClientPeer(
                    vk,
                    manager_to_handler_sender,
                ))
                .map_err(|e| Error::Other(e.to_string()))?;
            select! {
                _ = handler.handle_reader(&mut read) => {}
                _ = handler.handle_writer(&mut write, &mut manager_to_handler_receiver) => {}
            }
        }
        _ => {
            log::info!("Unkown peer connected: {}", vk);
            return Err(Error::InvalidMessage);
        }
    }
    Ok(())
}

// Verify the authenticity of the connection and return the public key of the remote peer
async fn authenticate(socket: &mut TcpStream, mailbox: &Mailbox) -> Result<PublicKey, Error> {
    // Send magic bytes
    socket.write_all(&MAGIC_BYTES).await?;

    // Receive and verify magic bytes
    let mut remote_magic = [0u8; 32];
    socket.read_exact(&mut remote_magic).await?;
    if remote_magic != MAGIC_BYTES {
        return Err(Error::AuthenticationFailed);
    }

    // Challenge-response authentication
    let mut csprng = OsRng;
    let mut challenge = [0u8; 32];
    csprng.fill_bytes(&mut challenge);

    socket.write_all(challenge.as_slice()).await?;

    let mut remote_challenge = [0u8; 32];
    socket.read_exact(&mut remote_challenge).await?;

    // Send public key
    socket.write_all(&mailbox.public_key().serialize()).await?;

    // Receive remote public key
    let mut remote_public_bytes = [0u8; 33];
    socket.read_exact(&mut remote_public_bytes).await?;
    let remote_public: PublicKey = PublicKey::from_byte_array_compressed(&remote_public_bytes)?;

    // Sign and send challenge response
    let message = mailbox.sign_message(remote_public, remote_challenge.to_vec())?;
    let encoded_message = message.encode();
    socket.write_all(&encoded_message).await?;

    // Verify remote response
    let mut response_bytes = [0u8; 170];
    socket.read_exact(&mut response_bytes).await?;
    let response = MailMessage::decode(&response_bytes)?;

    if response.verify()? {
        Ok(remote_public)
    } else {
        Err(Error::AuthenticationFailed)
    }
}

// Handles the connection for a router peer
struct RouterHandler {
    vk: PublicKey,
    handler_to_manager: Arc<UnboundedSender<HandlerToManager>>,
}

impl RouterHandler {
    // Handle the "read" side of the TCP socket
    async fn handle_reader(&self, read_half: &mut ReadHalf<'_>) -> Result<(), Error> {
        loop {
            let mut size_buf = [0u8; 4];
            let n = read_half.read(&mut size_buf).await?;
            if n < 4 {
                break;
            }
            let length = u32::from_be_bytes(size_buf) as usize;

            if length > 16 * 1024 {
                return Err(Error::InvalidMessage);
            }

            let mut frame = vec![0u8; length];
            read_half.read_exact(&mut frame).await?;
            let message_type = frame.get(0).ok_or(Error::InvalidMessage)?.clone();
            match message_type {
                0 => {
                    let message = MailMessage::decode(&frame[1..])?;
                    self.handler_to_manager
                        .send(HandlerToManager::MailReceived(message))
                        .map_err(|e| Error::Other(e.to_string()))?;
                }
                1 => {
                    let peer_change = self.read_peer_change(frame)?;
                    self.handler_to_manager
                        .send(HandlerToManager::RemotePeerChange(self.vk, peer_change))
                        .map_err(|e| Error::Other(e.to_string()))?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    // Parse the bytes of the given data frame into a PeerChange
    fn read_peer_change(&self, frame: Vec<u8>) -> Result<PeerChange, Error> {
        let change_type = frame.get(1).ok_or(Error::InvalidMessage)?.clone();
        let vk = PublicKey::from_byte_array_compressed(&frame[2..35].try_into()?)?;
        match change_type {
            // Remote peer has a new connection with a peer that has a public IP/port
            0 => {
                let ip_str_len = u16::from_be_bytes(
                    frame[35..37]
                        .try_into()
                        .map_err(|_| Error::InvalidMessage)?,
                ) as usize;
                let ip_str = std::str::from_utf8(&frame[37..37 + ip_str_len])
                    .map_err(|_| Error::InvalidMessage)?;
                let port = u16::from_be_bytes(
                    frame[37 + ip_str_len..37 + ip_str_len + 2]
                        .try_into()
                        .map_err(|_| Error::InvalidMessage)?,
                );
                Ok(PeerChange::AddPublic(vk, ip_str.to_owned(), port))
            }
            // Remote peer has a new connection with a peer that is private. It might be a client peer, or it might be another router.
            1 => Ok(PeerChange::AddPrivate(vk)),
            // Remote peer has lost a connection with a peer
            2 => Ok(PeerChange::Remove(vk)),
            // Remote peer is confused, and now we are too
            _ => Err(Error::InvalidMessage),
        }
    }

    // Handle the "write" side of the TCP socket
    async fn handle_writer(
        &self,
        write_half: &mut WriteHalf<'_>,
        manager_to_handler_receiver: &mut UnboundedReceiver<ManagerToHandler>,
    ) -> Result<(), Error> {
        while let Some(v) = manager_to_handler_receiver.recv().await {
            match v {
                ManagerToHandler::SendMessage(message) => {
                    let bytes = message.encode();
                    let size = bytes.len() as u32;
                    let size_bytes = size.to_be_bytes();
                    write_half.write_all(&size_bytes).await?;
                    write_half.write_all(&bytes).await?;
                }
            }
        }
        Ok(())
    }
}

// Handle the connection for a client peer
struct ClientHandler {
    vk: PublicKey,
    handler_to_manager: Arc<UnboundedSender<HandlerToManager>>,
}

impl ClientHandler {
    // Handle the "read" side of the TCP socket
    async fn handle_reader(&self, read_half: &mut ReadHalf<'_>) -> Result<(), Error> {
        loop {
            let mut size_buf = [0u8; 4];
            let n = read_half.read(&mut size_buf).await?;
            if n < 4 {
                break;
            }
            let length = u32::from_be_bytes(size_buf) as usize;

            if length > 16 * 1024 {
                return Err(Error::InvalidMessage);
            }

            let mut frame = vec![0u8; length];
            read_half.read_exact(&mut frame).await?;
            let message_type = frame.get(0).ok_or(Error::InvalidMessage)?.clone();
            if message_type == 0 {
                let message = MailMessage::decode(&frame[1..])?;
                self.handler_to_manager
                    .send(HandlerToManager::MailReceived(message))
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
        }

        Ok(())
    }

    // Handle the "write" side of the TCP socket
    async fn handle_writer(
        &self,
        write_half: &mut WriteHalf<'_>,
        manager_to_handler_receiver: &mut UnboundedReceiver<ManagerToHandler>,
    ) -> Result<(), Error> {
        while let Some(v) = manager_to_handler_receiver.recv().await {
            match v {
                ManagerToHandler::SendMessage(message) => {
                    let bytes = message.encode();
                    let size = bytes.len() as u32;
                    let size_bytes = size.to_be_bytes();
                    write_half.write_all(&size_bytes).await?;
                    write_half.write_all(&bytes).await?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
enum HandlerToManager {
    MailReceived(MailMessage),
    NewRouterPeer(PublicKey, UnboundedSender<ManagerToHandler>),
    NewClientPeer(PublicKey, UnboundedSender<ManagerToHandler>),
    RemotePeerChange(PublicKey, PeerChange),
}

#[derive(Debug)]
enum ManagerToHandler {
    SendMessage(MailMessage),
}

#[derive(Debug)]
enum PeerChange {
    AddPublic(PublicKey, String, u16),
    AddPrivate(PublicKey),
    Remove(PublicKey),
}

const MAGIC_BYTES: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F,
];

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Mutex error")]
    Mutex(),
    #[error("Invalid message format")]
    InvalidMessage,
    #[error("Invalid mail: {0}")]
    InvalidMail(crate::mail::Error),
    #[error("Other({0})")]
    Other(String),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::Mutex()
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::Other("Slice length invalid".to_owned())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

impl From<crate::mail::Error> for Error {
    fn from(e: crate::mail::Error) -> Self {
        Error::InvalidMail(e)
    }
}
