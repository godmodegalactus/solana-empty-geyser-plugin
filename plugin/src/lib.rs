use std::{net::{IpAddr, Ipv4Addr, UdpSocket}, sync::Arc};

use pem::Pem;
use quinn::{ServerConfig, IdleTimeout, Endpoint, TokioRuntime, EndpointConfig};
use serde::{Serialize, Deserialize};
use solana_geyser_plugin_interface::geyser_plugin_interface::{GeyserPlugin, Result as PluginResult, GeyserPluginError};
use solana_sdk::{signature::{Signature, Keypair}, transaction::TransactionError, slot_history::Slot, quic::QUIC_MAX_TIMEOUT, packet::PACKET_DATA_SIZE};
use solana_streamer::{tls_certificates::new_self_signed_tls_certificate, quic::QuicServerError};
use tokio::{runtime::Runtime, task::JoinHandle, sync::mpsc::{UnboundedSender, UnboundedReceiver}};

use crate::skip_client_verification::SkipClientVerification;

mod skip_client_verification;
mod plugin_error;

pub const ALPN_GEYSER_PROTOCOL_ID: &[u8] = b"solana-geyser";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionResults {
    signature: Signature,
    error: Option<TransactionError>,
    slot: Slot,
}

#[derive(Debug)]
pub struct PluginInner {
    pub runtime: Runtime,
    pub handle: JoinHandle<()>,
    pub sender: Arc<UnboundedSender<TransactionResults>>,
}

#[derive(Debug)]
pub struct Plugin {
    inner: Option<PluginInner>,
}

impl GeyserPlugin for Plugin {
    fn name(&self) -> &'static str {
        "geyser_quic_banking_transactions_result_sender"
    }

    fn banking_transaction_results_notifications_enabled(&self) -> bool {
        true
    }

    #[allow(unused_variables)]
    fn notify_banking_stage_transaction_results(
        &self,
        transaction: Signature,
        error: Option<TransactionError>,
        slot: Slot,
    ) -> PluginResult<()> {
        if let Some(inner) = self.inner {
            inner.sender.send(TransactionResults { signature: transaction, error, slot });
            Ok(())
        } else {
            Ok(())
        }
    }

    fn on_load(&mut self, _config_file: &str) -> solana_geyser_plugin_interface::geyser_plugin_interface::Result<()> {
        let runtime = Runtime::new().map_err(|error| GeyserPluginError::Custom(Box::new(error)))?;
        let res  = configure_server(&Keypair::new(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        
        let (config, _) = res.map_err(|error| GeyserPluginError::Custom(Box::new(error)))?;
        let sock = UdpSocket::bind("127.0.0.1:18990").expect("couldn't bind to address");
        let endpoint = Endpoint::new(EndpointConfig::default(), Some(config), sock, TokioRuntime)
        .map_err(|error| GeyserPluginError::Custom(Box::new(error)))?;
        let (sender, reciever) = tokio::sync::mpsc::unbounded_channel::<TransactionResults>();

        let handle = tokio::spawn(async move {
            let mut reciever = reciever;
            loop {
                let connecting = endpoint.accept().await;
                if let Some(connecting) = connecting {
                    let connected = connecting.await;
                    let connection = match connected {
                        Ok(connection) => connection,
                        Err(e) => {
                            log::error!("geyser plugin connecting {} error", e);
                            continue;
                        }
                    };
                    let (mut send_stream, _) = match connection.accept_bi().await {
                        Ok(res) => res,
                        Err(e) => {
                            log::error!("geyser plugin accepting bi-channel {} error", e);
                            continue;
                        }
                    };

                    while let Some(msg) = reciever.recv().await {
                        let bytes = bincode::serialize(&msg).unwrap_or(vec![]);
                        if !bytes.is_empty() {
                            let _ = send_stream.write_all(&bytes).await;
                        }
                    }
                }
            }
        });

        self.inner = Some(PluginInner {
            runtime,
            handle,
            sender: Arc::new(sender),
        });
        Ok(())
    }

    fn on_unload(&mut self) {}
}

pub(crate) fn configure_server(
    identity_keypair: &Keypair,
    host: IpAddr,
) -> Result<(ServerConfig, String), QuicServerError> {
    let (cert, priv_key) = new_self_signed_tls_certificate(identity_keypair, host)?;
    let cert_chain_pem_parts = vec![Pem {
        tag: "CERTIFICATE".to_string(),
        contents: cert.0.clone(),
    }];
    let cert_chain_pem = pem::encode_many(&cert_chain_pem_parts);

    let mut server_tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(SkipClientVerification::new())
        .with_single_cert(vec![cert], priv_key)?;
    server_tls_config.alpn_protocols = vec![ALPN_GEYSER_PROTOCOL_ID.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_tls_config));
    server_config.use_retry(true);
    let config = Arc::get_mut(&mut server_config.transport).unwrap();

    config.max_concurrent_uni_streams((0 as u32).into());
    let recv_size = (PACKET_DATA_SIZE as u32).into();
    config.stream_receive_window(recv_size);
    config.receive_window(recv_size);
    let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
    config.max_idle_timeout(Some(timeout));

    // disable bidi & datagrams
    const MAX_CONCURRENT_BIDI_STREAMS: u32 = 1;
    config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    config.datagram_receive_buffer_size(None);

    Ok((server_config, cert_chain_pem))
}