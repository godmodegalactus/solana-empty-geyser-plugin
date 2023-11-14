# Solana Geyser Quic Banking Stage Errors

This project aims to get banking stage transaction data over geyser from the leader.
There is a plugin which needs to be installed on leader. It will create a QUIC port and only accept connections from a known identity.
Once connection is accepted it will start sending the banking stage data over geyser to its suibscriber.

## Run solana validator with plugin

```bash
$ solana-validator --geyser-plugin-config config.json
```

