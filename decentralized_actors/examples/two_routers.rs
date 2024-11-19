use decentralized_actors::{mail::Mailbox, router::RouterSocketsManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Error> {
    simple_logger::SimpleLogger::new().init()?;
    select! {
        r = router0() => r?,
        r = router1() => r?,
    }
    Ok(())
}

async fn router0() -> Result<(), Error> {
    let mailbox = Mailbox::generate();
    let manager = RouterSocketsManager::new(mailbox);
    manager
        .serve(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8700))
        .await?;
    Ok(())
}

async fn router1() -> Result<(), Error> {
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let mailbox = Mailbox::generate();
    let manager = RouterSocketsManager::new(mailbox);
    let peer0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8700);
    manager.connect(peer0).await?;
    manager
        .serve(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8701))
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
