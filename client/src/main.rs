use std::{time::Duration, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};

use cli::Args;
use geyser_quic_plugin::{TransactionResults, ALPN_GEYSER_PROTOCOL_ID};
use quinn::{TokioRuntime, EndpointConfig, Endpoint, ClientConfig, TransportConfig, IdleTimeout};
use solana_quic_client::nonblocking::quic_client:: SkipServerVerification;
use solana_sdk::signature::Keypair;
use clap::Parser;
use solana_streamer::tls_certificates::new_self_signed_tls_certificate;

mod cli;

pub const PACKET_DATA_SIZE: usize = 1280 - 40 - 8;

pub async fn load_identity_keypair(identity_file: &String) -> Option<Keypair> {
    let identity_file = tokio::fs::read_to_string(identity_file.as_str())
        .await
        .expect("Cannot find the identity file provided");
    let identity_bytes: Vec<u8> = serde_json::from_str(&identity_file).unwrap();
    Some(Keypair::from_bytes(identity_bytes.as_slice()).unwrap())
}

pub fn create_endpoint(certificate: rustls::Certificate, key: rustls::PrivateKey) -> Endpoint {
    let mut endpoint = {
        let client_socket =
            solana_net_utils::bind_in_range(IpAddr::V4(Ipv4Addr::UNSPECIFIED), (8000, 10000))
                .expect("create_endpoint bind_in_range")
                .1;
        let config = EndpointConfig::default();
        quinn::Endpoint::new(config, None, client_socket, Arc::new(TokioRuntime))
            .expect("create_endpoint quinn::Endpoint::new")
    };

    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_client_auth_cert(vec![certificate], key)
        .expect("Failed to set QUIC client certificates");

    crypto.enable_early_data = true;
    crypto.alpn_protocols = vec![ALPN_GEYSER_PROTOCOL_ID.to_vec()];

    let mut config = ClientConfig::new(Arc::new(crypto));
    let mut transport_config = TransportConfig::default();

    let timeout = IdleTimeout::try_from(Duration::from_secs(3600 * 48)).unwrap();
    transport_config.max_idle_timeout(Some(timeout));
    transport_config.keep_alive_interval(Some(Duration::from_millis(500)));
    config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(config);

    endpoint
}

#[tokio::main()]
pub async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let address: SocketAddr = args.geyser_quic_address.parse().expect("should be valid socket address");

    let keypair = load_identity_keypair(&args.identity).await.expect("Identity file should be valid");

    let (certificate, key) = new_self_signed_tls_certificate(
        &keypair,
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
    )
    .expect("Failed to initialize QUIC client certificates");

    let endpoint = create_endpoint(certificate, key);
    let connection = endpoint.connect(address, "quic_geyser_plugin").expect("Should be connecting").await.expect("Should be able to connect to the plugin");
    let (_send_stream, recv_stream) = connection.open_bi().await.expect("Should be able to create a bi directional connection");

    tokio::spawn(async move {
        // wait for 10 s max
        let mut buffer: [u8; PACKET_DATA_SIZE] = [0; PACKET_DATA_SIZE];
        let mut recv_stream = recv_stream;
        loop {
            if let Ok(Some(size)) = recv_stream.read(&mut buffer ).await
            {
                let data = &buffer[0..size];
                if let Ok(result) = bincode::deserialize::<TransactionResults>(&data) {
                    println!("Transaction Result \n s:{} e:{} slt:{}", result.signature, result.error.map(|x| x.to_string()).unwrap_or_default(), result.slot);
                }
            }
        }
    });
    Ok(())
}
