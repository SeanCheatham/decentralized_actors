use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1};
use sha2::Digest;
use std::array::TryFromSliceError;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::broadcast::{self, Sender};

// An addressable+verifiable data message
#[derive(Debug, Clone)]
pub struct MailMessage {
    // The sender's public key
    pub sender: PublicKey,
    // The receiver's public key
    pub receiver: PublicKey,
    // The timestamp (UNIX epoch in ms) of the message. Also intended to be unique in the context of the two keys, like a sequence number with gaps.
    pub timestamp: u64,
    // The actual payload
    pub data: Vec<u8>,
    // A signature that can be verified using the provided sender's public key
    pub signature: Signature,
}

// A mailbox that can send and receive messages
#[derive(Clone)]
pub struct Mailbox {
    // Each mailbox has a secret key that can be used to sign outbound messages
    keypair: Keypair,
    message_sender: Sender<MailMessage>,
}

impl Mailbox {
    // Create a new mailbox using a provided keypair
    pub fn new(keypair: Keypair) -> Self {
        let (sender, _) = broadcast::channel(100);
        Self {
            keypair,
            message_sender: sender,
        }
    }

    // Generate a new keypair and create a mailbox from it
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let alg = Secp256k1::new();
        let keypair = Keypair::new(&alg, &mut csprng);
        Self::new(keypair)
    }

    // Extract this mailbox's public key
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    // Listen to any messages sent to this mailbox
    pub fn subscribe(&self) -> broadcast::Receiver<MailMessage> {
        self.message_sender.subscribe()
    }

    // Sends a message to this mailbox (and broadcasts it to any subscribers)
    pub fn receive(&self, message: MailMessage) -> Result<(), Error> {
        if message.verify()? {
            let _ = self.message_sender.send(message);
            Ok(())
        } else {
            Err(Error::InvalidMessage)
        }
    }

    // Signs a message to a specific recipient
    pub fn sign_message(&self, receiver: PublicKey, data: Vec<u8>) -> Result<MailMessage, Error> {
        // TODO: Make this a parameter
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let sender = self.public_key();

        // The format of the message to be signed: |sender|receiver|timestamp|data|
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(&sender.serialize());
        message_bytes.extend_from_slice(&receiver.serialize());
        // Timestamp is encoded into 8 bytes in big-endian format
        message_bytes.extend_from_slice(&timestamp.to_be_bytes());
        message_bytes.extend_from_slice(&data);
        let mut hasher = sha2::Sha256::new();
        hasher.update(data.clone());
        let m = Message::from_digest(hasher.finalize().to_vec().as_slice().try_into()?);

        let alg = Secp256k1::new();

        let signature = alg.sign_ecdsa(&m, &self.keypair.secret_key());

        Ok(MailMessage {
            sender,
            receiver,
            timestamp,
            data,
            signature,
        })
    }
}

impl MailMessage {
    // Serializes the message into a portable format
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sender.serialize());
        bytes.extend_from_slice(&self.receiver.serialize());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.signature.serialize_compact());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    // Decode the message from its portable format
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 138 {
            return Err(Error::InvalidMessage);
        }

        let sender = PublicKey::from_byte_array_compressed(&bytes[0..33].try_into()?)?;

        let receiver = PublicKey::from_byte_array_compressed(&bytes[33..66].try_into()?)?;
        let timestamp = u64::from_be_bytes(bytes[66..74].try_into().unwrap());
        let signature = Signature::from_compact(&bytes[74..138])?;
        let data = bytes[138..].to_vec();

        Ok(MailMessage {
            sender,
            receiver,
            timestamp,
            data,
            signature,
        })
    }

    // Checks the signature of the message to ensure the sender signed the correct data
    pub fn verify(&self) -> Result<bool, Error> {
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(&self.sender.serialize());
        message_bytes.extend_from_slice(&self.receiver.serialize());
        message_bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        message_bytes.extend_from_slice(&self.data);
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.data.clone());
        let m = Message::from_digest(hasher.finalize().to_vec().as_slice().try_into()?);

        let secp256k1 = secp256k1::Secp256k1::new();

        secp256k1.verify_ecdsa(&m, &self.signature, &self.sender)?;
        Ok(true)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid message format")]
    InvalidMessage,
    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::InvalidMessage
    }
}
