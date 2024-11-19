use decentralized_actors::{mail::Mailbox, router::RouterSocketsManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Error> {
    simple_logger::SimpleLogger::new().init()?;
    let mailbox = Mailbox::generate();
    let manager = RouterSocketsManager::new(mailbox);
    manager
        .serve(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8700))
        .await?;
    Ok(())
}

#[derive(Debug)]
enum Error {
    Router(decentralized_actors::router::Error),
    LoggerError(),
}

impl From<decentralized_actors::router::Error> for Error {
    fn from(e: decentralized_actors::router::Error) -> Self {
        Error::Router(e)
    }
}

impl From<log::SetLoggerError> for Error {
    fn from(_: log::SetLoggerError) -> Self {
        Error::LoggerError()
    }
}
