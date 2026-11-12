use console::style;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};
use tokio::time::Instant;

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

struct WaitingPeer {
    pair_tx: oneshot::Sender<(TcpStream, SocketAddr)>,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    connected_at: Instant,
}

type RelayState = Arc<Mutex<HashMap<String, WaitingPeer>>>;

pub async fn run_relay(bind: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let local_addr = listener.local_addr()?;

    println!();
    println!("{}", style("╭────────────────────────────────────────────────────────────────╮").cyan());
    println!("{}", style("│   VOIDHOP ⇄ Encrypted Transit Relay Server                     │").cyan().bold());
    println!("{}", style("╰────────────────────────────────────────────────────────────────╯").cyan());
    println!();
    println!("  {:<15} {}", style("Listening on:").bold(), style(local_addr.to_string()).yellow().bold());
    println!("  {:<15} {}", style("Status:").bold(), style("Ready to bridge peer connections").green());
    println!();
    println!("  {:<15} {}", style("Usage:").bold(), style(format!("voidhop <file> --relay {}", local_addr)).cyan());
    println!("  {:<15} {}", style("Env Var:").bold(), style(format!("VOIDHOP_RELAY={}", local_addr)).dim());
    println!();
    println!("{}", style("Waiting for peer connections...").dim());

    let state: RelayState = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("{} Failed to accept connection: {}", style("!").yellow(), e);
                continue;
            }
        };

        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, state_clone).await {
                // Connection errors or clean disconnects
                let _ = e;
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: RelayState,
) -> io::Result<()> {
    // 1. Read handshake line (max 256 bytes)
    let mut line_buf = Vec::new();
    let mut byte = [0u8; 1];
    while line_buf.len() < 256 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Ok(());
        }
        if byte[0] == b'\n' {
            break;
        }
        line_buf.push(byte[0]);
    }

    let line = String::from_utf8_lossy(&line_buf);
    let trimmed = line.trim();

    // Protocol: "please relay <token>"
    let token = match trimmed.strip_prefix("please relay ") {
        Some(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => {
            stream.write_all(b"bad handshake\n").await?;
            return Ok(());
        }
    };

    let token_short = if token.len() >= 8 { &token[..8] } else { &token };

    // 2. Check if a partner is already waiting for this token
    let waiting_partner = {
        let mut lock = state.lock().await;
        lock.remove(&token)
    };

    if let Some(partner) = waiting_partner {
        // We are the second peer! Send our stream to the waiting peer
        if partner.pair_tx.send((stream, peer_addr)).is_err() {
            // First peer hung up right before pairing; we don't proceed
            return Ok(());
        }
    } else {
        // We are the first peer to arrive. Register in state and wait for partner.
        println!(
            "  {} [{}] Peer connected from {}, waiting for partner...",
            style("→").dim(),
            style(token_short).magenta(),
            style(peer_addr.to_string()).cyan()
        );
        let (pair_tx, pair_rx) = oneshot::channel::<(TcpStream, SocketAddr)>();
        {
            let mut lock = state.lock().await;
            lock.insert(
                token.clone(),
                WaitingPeer {
                    pair_tx,
                    peer_addr,
                    connected_at: Instant::now(),
                },
            );
        }

        // Wait for either: partner arriving, socket disconnect, or 10-minute timeout
        let mut monitor_buf = [0u8; 1];
        tokio::select! {
            result = pair_rx => {
                match result {
                    Ok((mut partner_stream, partner_addr)) => {
                        println!(
                            "{} [{}] Bridged peers {} ⇄ {}",
                            style("●").green().bold(),
                            style(token_short).magenta(),
                            style(peer_addr.to_string()).cyan(),
                            style(partner_addr.to_string()).cyan()
                        );

                        // Send "ok\n" acknowledgement to both peers
                        let ack_a = stream.write_all(b"ok\n");
                        let ack_b = partner_stream.write_all(b"ok\n");
                        if let (Ok(()), Ok(())) = tokio::join!(ack_a, ack_b) {
                            match tokio::io::copy_bidirectional(&mut stream, &mut partner_stream).await {
                                Ok((to_b, to_a)) => {
                                    let total = to_b + to_a;
                                    println!(
                                        "{} [{}] Transfer completed successfully ({})",
                                        style("✔").green().bold(),
                                        style(token_short).dim(),
                                        format_bytes(total)
                                    );
                                }
                                Err(_) => {
                                    println!(
                                        "{} [{}] Session closed",
                                        style("•").dim(),
                                        style(token_short).dim()
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            // If the waiting peer hangs up before partner arrives
            _ = stream.read(&mut monitor_buf) => {
                let mut lock = state.lock().await;
                lock.remove(&token);
            }
            // Timeout after 10 minutes of waiting
            _ = tokio::time::sleep(Duration::from_secs(600)) => {
                let mut lock = state.lock().await;
                lock.remove(&token);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::connect_relay;

    #[tokio::test]
    async fn test_local_relay_server_bridging() {
        // Bind relay to random ephemeral port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();

        let state: RelayState = Arc::new(Mutex::new(HashMap::new()));
        let state_clone = Arc::clone(&state);

        let relay_task = tokio::spawn(async move {
            while let Ok((stream, peer_addr)) = listener.accept().await {
                let s = Arc::clone(&state_clone);
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, s).await;
                });
            }
        });

        let test_token = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";

        // Client 1 connects
        let addr1 = relay_addr.clone();
        let tok1 = test_token.to_string();
        let client1_fut = tokio::spawn(async move {
            connect_relay(&addr1, &tok1).await
        });

        // Client 2 connects shortly after
        let addr2 = relay_addr.clone();
        let tok2 = test_token.to_string();
        let client2_fut = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            connect_relay(&addr2, &tok2).await
        });

        let (res1, res2) = tokio::join!(client1_fut, client2_fut);
        let mut s1 = res1.unwrap().expect("Client 1 should connect to relay");
        let mut s2 = res2.unwrap().expect("Client 2 should connect to relay");

        // Test bi-directional byte transfer
        s1.write_all(b"PING_RELAY_TEST").await.unwrap();
        let mut buf = [0u8; 15];
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING_RELAY_TEST");

        s2.write_all(b"PONG_RELAY_TEST").await.unwrap();
        let mut buf2 = [0u8; 15];
        s1.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"PONG_RELAY_TEST");

        relay_task.abort();
    }

    #[tokio::test]
    async fn test_relay_rejects_bad_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();

        let state: RelayState = Arc::new(Mutex::new(HashMap::new()));
        let state_clone = Arc::clone(&state);

        let relay_task = tokio::spawn(async move {
            if let Ok((stream, peer_addr)) = listener.accept().await {
                let _ = handle_connection(stream, peer_addr, state_clone).await;
            }
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        client.write_all(b"not a valid handshake\n").await.unwrap();

        let mut resp = [0u8; 14];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"bad handshake\n");

        relay_task.abort();
    }
}
