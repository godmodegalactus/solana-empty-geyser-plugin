use std::{
    net::{IpAddr, Ipv4Addr, UdpSocket},
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use crate::{config::Config, tls_certificate::new_self_signed_tls_certificate};
use itertools::Itertools;
use pem::Pem;
use quinn::{Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime};
use serde::{Deserialize, Serialize};
use solana_geyser_plugin_interface::geyser_plugin_interface::{
    GeyserPlugin, GeyserPluginError, Result as PluginResult,
};
use solana_sdk::{
    packet::PACKET_DATA_SIZE,
    pubkey::Pubkey,
    quic::QUIC_MAX_TIMEOUT,
    signature::{Keypair, Signature},
    slot_history::Slot,
    transaction::{SanitizedTransaction, TransactionError}, compute_budget::{self, ComputeBudgetInstruction}, borsh0_10::try_from_slice_unchecked,
};
use tls_certificate::get_pubkey_from_tls_certificate;
use tokio::{runtime::Runtime, sync::mpsc::UnboundedSender, task::JoinHandle};

use crate::skip_client_verification::SkipClientVerification;

pub mod skip_client_verification;
pub mod config;
pub mod tls_certificate;

pub const ALPN_GEYSER_PROTOCOL_ID: &[u8] = b"solana-geyser";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionResults {
    pub signature: Signature,
    pub error: Option<TransactionError>,
    pub slot: Slot,
    pub writable_accounts: Vec<Pubkey>,
    pub readable_accounts: Vec<Pubkey>,
    pub cu_requested: u64,
    pub prioritization_fees : u64,
}

fn decode_cu_requested_and_prioritization_fees(transaction: &SanitizedTransaction,) -> (u64, u64) {
    let mut cu_requested:u64 = 200_000;
    let mut prioritization_fees: u64 = 0;
    let accounts = transaction.message().account_keys().iter().map(|x| *x).collect_vec();
    for ix in transaction.message().instructions() {
        if ix.program_id(accounts.as_slice())
                    .eq(&compute_budget::id())
        {
            let cb_ix = try_from_slice_unchecked::<ComputeBudgetInstruction>(ix.data.as_slice());
            if let Ok(ComputeBudgetInstruction::RequestUnitsDeprecated {
                units,
                additional_fee,
            }) = cb_ix
            {
                if additional_fee > 0 {
                    return (units as u64, ((units * 1000) / additional_fee) as u64);
                } else {
                    return (units as u64, 0);
                }
            } else if let Ok(ComputeBudgetInstruction::SetComputeUnitLimit(units)) = cb_ix {
                cu_requested = units as u64;
            } else if let Ok(ComputeBudgetInstruction::SetComputeUnitPrice(price)) = cb_ix {
                prioritization_fees = price;
            }
        }
    }
    (cu_requested, prioritization_fees)
}

#[derive(Debug)]
pub struct PluginInner {
    pub runtime: Runtime,
    pub handle: JoinHandle<()>,
    pub sender: Arc<UnboundedSender<TransactionResults>>,
    pub start_sending: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
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
        transaction: &SanitizedTransaction,
        error: Option<TransactionError>,
        slot: Slot,
    ) -> PluginResult<()> {
        if let Some(inner) = &self.inner {
            if !inner.start_sending.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(())
            }
            if transaction.is_simple_vote_transaction() {
                return Ok(())
            }
            let message = transaction.message();

            let accounts = message.account_keys();
            let is_writable = accounts.iter().enumerate().map(|(index, _)| {
                transaction.message().is_writable(index)
            }).collect_vec();
            let mut writable_accounts = is_writable.iter().enumerate().filter(|(_, v)| **v).map(|(index, get_mut)| accounts[index]).collect_vec();
            let mut readable_accounts = is_writable.iter().enumerate().filter(|(_, v)| !**v).map(|(index, get_mut)| accounts[index]).collect_vec();
            writable_accounts.truncate(32);
            readable_accounts.truncate(32);

            let (cu_requested, prioritization_fees) = decode_cu_requested_and_prioritization_fees(transaction);

            if let Err(e) = inner.sender.send(TransactionResults {
                signature: transaction.signature().clone(),
                error,
                slot,
                writable_accounts,
                readable_accounts,
                cu_requested,
                prioritization_fees,
            }) {
                log::error!("error sending on the channel {e:?}");
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    fn on_load(
        &mut self,
        config_file: &str,
    ) -> solana_geyser_plugin_interface::geyser_plugin_interface::Result<()> {
        let plugin_config = Config::load_from_file(config_file)?;
        let runtime = Runtime::new().map_err(|error| GeyserPluginError::Custom(Box::new(error)))?;
        let res = configure_server(&Keypair::new(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

        let (config, _) = res.map_err(|_| GeyserPluginError::TransactionUpdateError { msg: "error configuring server".to_string() })?;
        let sock = UdpSocket::bind(plugin_config.quic_plugin.address).expect("couldn't bind to address");
        
        let (sender, reciever) = tokio::sync::mpsc::unbounded_channel::<TransactionResults>();

        let allowed_connection =
            Pubkey::from_str("G8pLuvzarejjLuuPNVNR1gk9xiFKmAcs9J5LL3GZGM6F").unwrap();
        let start_sending = Arc::new(AtomicBool::new(false));
        let start_sending_cp = start_sending.clone();

        let handle = runtime.block_on(async move {
            let mut reciever = reciever;
            let endpoint = Endpoint::new(EndpointConfig::default(), Some(config), sock, Arc::new(TokioRuntime)).expect("Should be able to create endpoint");
            tokio::spawn(async move {
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
                        let connection_identity = get_remote_pubkey(&connection);
                        if let Some(connection_identity) = connection_identity {
                            if !allowed_connection.eq(&connection_identity) {
                                // not an authorized connection
                                continue;
                            }
                        } else {
                            continue;
                        }
                        let (mut send_stream, _) = match connection.accept_bi().await {
                            Ok(res) => res,
                            Err(e) => {
                                log::error!("geyser plugin accepting bi-channel {} error", e);
                                continue;
                            }
                        };

                        start_sending_cp.store(true, std::sync::atomic::Ordering::Relaxed);
                        while let Some(msg) = reciever.recv().await {
                            let bytes = bincode::serialize(&msg).unwrap_or(vec![]);
                            if !bytes.is_empty() {
                                if let Err(e) = send_stream.write_all(&bytes).await {
                                    log::error!("error writing on stream channel {}", e);
                                }
                            }
                        }
                        start_sending_cp.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
        });

        self.inner = Some(PluginInner {
            runtime,
            handle,
            sender: Arc::new(sender),
            start_sending,
        });
        Ok(())
    }

    fn on_unload(&mut self) {}
}

pub(crate) fn configure_server(
    identity_keypair: &Keypair,
    host: IpAddr,
) -> anyhow::Result<(ServerConfig, String)> {
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

    config.max_concurrent_uni_streams((1 as u32).into());
    let recv_size = (PACKET_DATA_SIZE as u32 * 100).into();
    config.stream_receive_window(recv_size);
    config.receive_window(recv_size);
    let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
    config.max_idle_timeout(Some(timeout));

    // disable bidi & datagrams
    const MAX_CONCURRENT_BIDI_STREAMS: u32 = 10;
    config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    config.datagram_receive_buffer_size(None);

    Ok((server_config, cert_chain_pem))
}

pub fn get_remote_pubkey(connection: &quinn::Connection) -> Option<Pubkey> {
    // Use the client cert only if it is self signed and the chain length is 1.
    connection
        .peer_identity()?
        .downcast::<Vec<rustls::Certificate>>()
        .ok()
        .filter(|certs| certs.len() == 1)?
        .first()
        .and_then(get_pubkey_from_tls_certificate)
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub unsafe extern "C" fn _create_plugin() -> *mut dyn GeyserPlugin {
    let plugin = Plugin::default();
    let plugin: Box<dyn GeyserPlugin> = Box::new(plugin);
    Box::into_raw(plugin)
}
