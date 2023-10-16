use std::{sync::Arc, net::{SocketAddr, UdpSocket, IpAddr, Ipv4Addr}, time::Duration};

use quinn::{Connection, Endpoint, ConnectionError, EndpointConfig, TokioRuntime, ClientConfig, TransportConfig, IdleTimeout};
use solana_net_utils::PortRange;
use solana_quic_client::nonblocking::quic_client::QuicClientCertificate;
use solana_sdk::{signature::Keypair, quic::{QUIC_MAX_TIMEOUT, QUIC_KEEP_ALIVE}};
use solana_streamer::tls_certificates::new_self_signed_tls_certificate;
use tokio::{time::timeout, sync::OnceCell};
use geyser_quic_plugin::ALPN_GEYSER_PROTOCOL_ID;

pub const QUIC_CONNECTION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
pub const PORT_RANGE: PortRange = (8000, 20_000);

// This code is copied from solana

/// A lazy-initialized Quic Endpoint
pub struct QuicLazyInitializedEndpoint {
    endpoint: OnceCell<Arc<Endpoint>>,
    client_certificate: Arc<QuicClientCertificate>,
    client_endpoint: Option<Endpoint>,
}


impl QuicLazyInitializedEndpoint {
    pub fn new(
        client_certificate: Arc<QuicClientCertificate>,
        client_endpoint: Option<Endpoint>,
    ) -> Self {
        Self {
            endpoint: OnceCell::<Arc<Endpoint>>::new(),
            client_certificate,
            client_endpoint,
        }
    }

    fn create_endpoint(&self) -> Endpoint {
        let mut endpoint = if let Some(endpoint) = &self.client_endpoint {
            endpoint.clone()
        } else {
            let client_socket = solana_net_utils::bind_in_range(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                PORT_RANGE,
            )
            .expect("QuicLazyInitializedEndpoint::create_endpoint bind_in_range")
            .1;

            QuicNewConnection::create_endpoint(EndpointConfig::default(), client_socket)
        };

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_single_cert(
                vec![self.client_certificate.certificate.clone()],
                self.client_certificate.key.clone(),
            )
            .expect("Failed to set QUIC client certificates");

        crypto.enable_early_data = true;
        crypto.alpn_protocols = vec![ALPN_GEYSER_PROTOCOL_ID.to_vec()];

        let mut config = ClientConfig::new(Arc::new(crypto));
        let mut transport_config = TransportConfig::default();

        let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
        transport_config.max_idle_timeout(Some(timeout));
        transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
        config.transport_config(Arc::new(transport_config));

        endpoint.set_default_client_config(config);

        endpoint
    }

    async fn get_endpoint(&self) -> Arc<Endpoint> {
        self.endpoint
            .get_or_init(|| async { Arc::new(self.create_endpoint()) })
            .await
            .clone()
    }
}

impl Default for QuicLazyInitializedEndpoint {
    fn default() -> Self {
        let (cert, priv_key) =
            new_self_signed_tls_certificate(&Keypair::new(), IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .expect("Failed to create QUIC client certificate");
        Self::new(
            Arc::new(QuicClientCertificate {
                certificate: cert,
                key: priv_key,
            }),
            None,
        )
    }
}


#[derive(Clone)]
struct QuicNewConnection {
    endpoint: Arc<Endpoint>,
    connection: Arc<Connection>,
}

impl QuicNewConnection {
    /// Create a QuicNewConnection given the remote address 'addr'.
    async fn make_connection(
        endpoint: Arc<QuicLazyInitializedEndpoint>,
        addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        let endpoint = endpoint.get_endpoint().await;

        let connecting = endpoint.connect(addr, "connect")?;
        if let Ok(connecting_result) = timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, connecting).await
        {
            let connection = connecting_result?;

            Ok(Self {
                endpoint,
                connection: Arc::new(connection),
            })
        } else {
            Err(ConnectionError::TimedOut.into())
        }
    }

    fn create_endpoint(config: EndpointConfig, client_socket: UdpSocket) -> Endpoint {
        quinn::Endpoint::new(config, None, client_socket, TokioRuntime)
            .expect("QuicNewConnection::create_endpoint quinn::Endpoint::new")
    }

    // Attempts to make a faster connection by taking advantage of pre-existing key material.
    // Only works if connection to this endpoint was previously established.
    async fn make_connection_0rtt(
        &mut self,
        addr: SocketAddr,
    ) -> anyhow::Result<Arc<Connection>> {
        let connecting = self.endpoint.connect(addr, "connect")?;
        let connection = match connecting.into_0rtt() {
            Ok((connection, zero_rtt)) => {
                if let Ok(zero_rtt) = timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, zero_rtt).await {
                    connection
                } else {
                    return Err(ConnectionError::TimedOut.into());
                }
            }
            Err(connecting) => {

                if let Ok(connecting_result) =
                    timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, connecting).await
                {
                    connecting_result?
                } else {
                    return Err(ConnectionError::TimedOut.into());
                }
            }
        };
        self.connection = Arc::new(connection);
        Ok(self.connection.clone())
    }
}

pub struct SkipServerVerification;

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}