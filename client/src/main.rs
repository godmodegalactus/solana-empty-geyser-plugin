use std::time::{Instant, Duration};

use geyser_quic_plugin::TransactionResults;

mod quic_connection;

pub const PACKET_DATA_SIZE: usize = 1280 - 40 - 8;

#[tokio::main()]
pub async fn main() {
    tokio::spawn(async move {
        // wait for 10 s max
        let mut timeout: u64 = 10_000;
        let mut start = Instant::now();

        const LAST_BUFFER_SIZE: usize = QUIC_MESSAGE_SIZE + 1;
        let mut last_buffer: [u8; LAST_BUFFER_SIZE] = [0; LAST_BUFFER_SIZE];
        let mut buffer_written = 0;
        let mut recv_stream = recv_stream;
        loop {
            if let Ok(chunk) = tokio::time::timeout(
                Duration::from_millis(timeout),
                recv_stream.read_chunk(PACKET_DATA_SIZE, false),
            )
            .await {

            }
        }
    });
}