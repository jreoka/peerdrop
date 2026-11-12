use crate::archive::{prepare_payload, unpack_payload};
use crate::crypto::{hex_encode, SessionKeys};
use crate::network::{
    connect_relay, create_p2p_node, get_relay_address, protocol_for_room, StreamConnection, Ticket,
};
use crate::protocol::{
    read_encrypted_frame, recv_json_msg, send_json_msg, write_encrypted_frame,
    AuthChallengeMsg, AuthFinalMsg, AuthResponseMsg, ReceiverDecision, TransferAck,
    TransferFinish, TransferMeta, CHUNK_SIZE, PROTOCOL_VERSION,
};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;

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

pub async fn run_sender(
    source_path: &Path,
    custom_code: Option<String>,
    relay_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Prepare and hash payload
    println!("{}", style("Scanning and preparing payload...").dim());
    let mut payload = prepare_payload(source_path)?;

    // 2. Determine transfer code
    let code = match custom_code {
        Some(c) => {
            let normalized = crate::words::normalize_code(&c);
            if normalized.is_empty() {
                return Err("Custom code cannot be empty".into());
            }
            normalized
        }
        None => crate::words::generate_code(),
    };
    let keys = SessionKeys::from_code(&code)?;

    // 3. Initialize P2P node
    let mut node = create_p2p_node()?;
    let protocol = protocol_for_room(&keys.room_id);
    let mut incoming_streams = node.stream_control.accept(protocol)?;

    // 4. Drive swarm and extract listen port
    let (port_tx, port_rx) = oneshot::channel();
    let mut port_tx_opt = Some(port_tx);

    let swarm_handle = tokio::spawn(async move {
        loop {
            let event = node.swarm.select_next_some().await;
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    for component in address.iter() {
                        if let libp2p::multiaddr::Protocol::Tcp(port) = component
                            && let Some(tx) = port_tx_opt.take()
                        {
                            let _ = tx.send((port, address.clone()));
                        }
                    }
                }
                SwarmEvent::Behaviour(crate::network::AppBehaviourEvent::Mdns(
                    libp2p::mdns::Event::Discovered(peers),
                )) => {
                    for (peer_id, addr) in peers {
                        node.swarm.add_peer_address(peer_id, addr);
                    }
                }
                _ => {}
            }
        }
    });

    let _ = port_rx.await;

    // 5. Print sleek croc-style sender interface
    println!();
    println!("{}", style("╭────────────────────────────────────────────────────────────────╮").cyan());
    println!("{}", style("│   VOIDHOP ⇄ Encrypted File Transfer                            │").cyan().bold());
    println!("{}", style("╰────────────────────────────────────────────────────────────────╯").cyan());
    println!();
    let kind = if payload.meta.is_directory {
        format!("Directory ({} files)", payload.meta.file_count)
    } else {
        "File".to_string()
    };
    println!("  {:<12} {} ({}, {})", style("Payload:").bold(), style(&payload.meta.name).yellow().bold(), kind, format_bytes(payload.meta.total_bytes));
    println!("  {:<12} {}", style("SHA-256:").bold(), style(&payload.meta.sha256).dim());
    println!("  {:<12} {}", style("Security:").bold(), style("ChaCha20-Poly1305 + Noise Handshake").green());
    println!();
    println!("  {:<12} {}", style("Code:").bold(), style(&code).magenta().bold());
    println!();
    println!("  {}", style("► To receive, run:").bold());
    println!("    {}", style(format!("voidhop {}", code)).bold().cyan());
    println!();
    println!("{}", style("Waiting for recipient to connect...").dim());

    let (stream_tx, mut stream_rx) = mpsc::channel::<(String, StreamConnection)>(8);

    // Forward LAN / mDNS incoming streams
    let tx_lan = stream_tx.clone();
    let lan_task = tokio::spawn(async move {
        while let Some((peer_id, raw_stream)) = incoming_streams.next().await {
            let conn = StreamConnection::P2p(raw_stream.compat());
            if tx_lan.send((format!("LAN peer {}", peer_id), conn)).await.is_err() {
                break;
            }
        }
    });

    // Forward Internet relay incoming stream
    let tx_relay = stream_tx.clone();
    let relay_addr = get_relay_address(relay_override);
    let relay_token = keys.transit_token();
    let relay_task = tokio::spawn(async move {
        loop {
            match connect_relay(&relay_addr, &relay_token).await {
                Ok(tcp_stream) => {
                    let conn = StreamConnection::Tcp(tcp_stream);
                    if tx_relay.send(("Internet relay".to_string(), conn)).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });

    // 6. Wait for recipient to connect; loop to handle connection attempts resiliently
    while let Some((source, mut stream)) = stream_rx.recv().await {
        println!();
        println!("{} Connected to peer via {}", style("✔").green().bold(), style(&source).cyan());
        println!("{}", style("Performing zero-knowledge cryptographic handshake...").dim());

        // Handshake: read challenge from receiver (direction 1, frame 0)
        let auth_challenge: AuthChallengeMsg = match recv_json_msg(&mut stream, &keys, 0, 1).await {
            Ok(msg) => msg,
            Err(e) => {
                println!("{} Handshake failed for {}: {}", style("!").yellow(), source, e);
                println!("{}", style("Waiting for recipient to connect...").dim());
                continue;
            }
        };

        if auth_challenge.version != PROTOCOL_VERSION {
            println!(
                "{} Rejected peer {}: incompatible protocol version {}",
                style("!").yellow(),
                source,
                auth_challenge.version
            );
            println!("{}", style("Waiting for recipient to connect...").dim());
            continue;
        }

        let mut sender_challenge = [0u8; 32];
        rand::fill(&mut sender_challenge);

        let auth_response = keys.compute_auth_response(&auth_challenge.challenge);
        let resp_msg = AuthResponseMsg {
            response: auth_response,
            peer_challenge: sender_challenge,
        };

        // Send response and our challenge (direction 0, frame 0)
        if let Err(e) = send_json_msg(&mut stream, &keys, 0, 0, &resp_msg).await {
            println!("{} Failed sending auth response to {}: {}", style("!").yellow(), source, e);
            println!("{}", style("Waiting for recipient to connect...").dim());
            continue;
        }

        // Read receiver's final response (direction 1, frame 1)
        let auth_final: AuthFinalMsg = match recv_json_msg(&mut stream, &keys, 1, 1).await {
            Ok(msg) => msg,
            Err(e) => {
                println!("{} Handshake failed for {}: {}", style("!").yellow(), source, e);
                println!("{}", style("Waiting for recipient to connect...").dim());
                continue;
            }
        };

        if !keys.verify_auth_response(&sender_challenge, &auth_final.response) {
            println!(
                "{} Peer authentication failed for {}: transfer code mismatch!",
                style("✖").red().bold(),
                source
            );
            println!("{}", style("Waiting for recipient to connect...").dim());
            continue;
        }

        println!("{} Authentication verified. Code matches!", style("✔").green().bold());

        // Send transfer metadata (direction 0, frame 1)
        send_json_msg(&mut stream, &keys, 1, 0, &payload.meta).await?;
        println!("{}", style("Waiting for recipient to accept transfer...").dim());

        // Read recipient decision (direction 1, frame 2)
        let decision: ReceiverDecision = recv_json_msg(&mut stream, &keys, 2, 1).await?;
        if !decision.accepted {
            let reason = decision.reason.unwrap_or_else(|| "Declined by recipient".into());
            println!("{} Transfer aborted: {}", style("✖").red().bold(), reason);
            swarm_handle.abort();
            lan_task.abort();
            relay_task.abort();
            return Ok(());
        }

        println!("{} Recipient accepted! Starting transfer...", style("✔").green().bold());
        println!();

        // 7. Stream data with progress bar
        let pb = if io::stdout().is_terminal() {
            let p = ProgressBar::new(payload.meta.total_bytes);
            p.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            p
        } else {
            ProgressBar::hidden()
        };

        let mut chunk_buf = vec![0u8; CHUNK_SIZE];
        let mut chunk_index: u64 = 2; // frames 0 and 1 were handshake and metadata
        let mut total_sent: u64 = 0;

        loop {
            let n = payload.file.read(&mut chunk_buf)?;
            if n == 0 {
                break;
            }
            write_encrypted_frame(&mut stream, &keys, chunk_index, 0, &chunk_buf[..n]).await?;
            pb.inc(n as u64);
            total_sent += n as u64;
            chunk_index += 1;
        }
        pb.finish_with_message("Done");

        if total_sent != payload.meta.total_bytes {
            return Err(format!(
                "Incomplete payload sent: read {} bytes, expected {}",
                total_sent, payload.meta.total_bytes
            )
            .into());
        }

        // Send transfer finish message
        let finish_msg = TransferFinish {
            sha256: payload.meta.sha256.clone(),
        };
        send_json_msg(&mut stream, &keys, chunk_index, 0, &finish_msg).await?;

        // Await recipient verification ack (direction 1, frame 3)
        let ack: TransferAck = recv_json_msg(&mut stream, &keys, 3, 1).await?;
        println!();
        if ack.verified {
            println!("{}", style("✔ Transfer complete! Recipient successfully verified SHA-256 data integrity.").green().bold());
        } else {
            println!("{} Recipient reported integrity verification failure: {}", style("✖").red().bold(), ack.message);
        }

        swarm_handle.abort();
        lan_task.abort();
        relay_task.abort();
        return Ok(());
    }

    swarm_handle.abort();
    Err("Stream listener closed without connection".into())
}

pub async fn run_receiver(
    code_or_ticket: &str,
    target_dir: Option<PathBuf>,
    auto_accept: bool,
    relay_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest_dir = target_dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // 1. Parse ticket/code
    let ticket = Ticket::from_str(code_or_ticket)
        .map_err(|e| format!("Invalid code or ticket: {}", e))?;
    let code = crate::words::normalize_code(&ticket.c);
    if code.is_empty() {
        return Err("Transfer code cannot be empty".into());
    }
    let keys = SessionKeys::from_code(&code)?;

    println!();
    println!("{}", style("╭────────────────────────────────────────────────────────────────╮").cyan());
    println!("{}", style("│   VOIDHOP ⇄ Encrypted File Transfer                            │").cyan().bold());
    println!("{}", style("╰────────────────────────────────────────────────────────────────╯").cyan());
    println!();
    println!("  {:<12} {}", style("Code:").bold(), style(&code).magenta().bold());
    println!("  {:<12} {}", style("Target Dir:").bold(), style(dest_dir.display().to_string()).yellow());

    // 2. Initialize P2P node
    let mut node = create_p2p_node()?;
    let protocol = protocol_for_room(&keys.room_id);

    let (peer_connected_tx, mut peer_connected_rx) = mpsc::channel::<libp2p::PeerId>(16);

    let mut direct_addresses: Vec<Multiaddr> = Vec::new();
    for addr_str in &ticket.a {
        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
            direct_addresses.push(addr);
        }
    }

    let is_direct = !direct_addresses.is_empty();
    if is_direct {
        println!("  {}", style("► Connecting directly to peer address...").dim());
        for addr in &direct_addresses {
            let _ = node.swarm.dial(addr.clone());
        }
    } else {
        println!("  {}", style("► Connecting to peer (LAN & Internet)...").dim());
    }

    let direct_addrs_clone = direct_addresses.clone();
    let swarm_handle = tokio::spawn(async move {
        let mut redial_interval = tokio::time::interval(Duration::from_secs(2));
        redial_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = node.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(crate::network::AppBehaviourEvent::Mdns(
                            libp2p::mdns::Event::Discovered(peers),
                        )) => {
                            for (peer_id, addr) in peers {
                                node.swarm.add_peer_address(peer_id, addr);
                                let _ = node.swarm.dial(peer_id);
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let _ = peer_connected_tx.send(peer_id).await;
                        }
                        _ => {}
                    }
                }
                _ = redial_interval.tick(), if !direct_addrs_clone.is_empty() => {
                    for addr in &direct_addrs_clone {
                        let _ = node.swarm.dial(addr.clone());
                    }
                }
            }
        }
    });

    let (stream_tx, mut stream_rx) = mpsc::channel::<(String, StreamConnection)>(8);

    // Forward LAN / mDNS incoming streams
    let tx_lan = stream_tx.clone();
    let stream_control = node.stream_control.clone();
    let protocol_clone = protocol.clone();
    let lan_task = tokio::spawn(async move {
        while let Some(peer_id) = peer_connected_rx.recv().await {
            let tx = tx_lan.clone();
            let mut ctrl = stream_control.clone();
            let prot = protocol_clone.clone();
            tokio::spawn(async move {
                for attempt in 0..3 {
                    match ctrl.open_stream(peer_id, prot.clone()).await {
                        Ok(st) => {
                            let conn = StreamConnection::P2p(st.compat());
                            let _ = tx.send((format!("LAN peer {}", peer_id), conn)).await;
                            break;
                        }
                        Err(_) => {
                            if attempt < 2 {
                                tokio::time::sleep(Duration::from_millis(250)).await;
                            }
                        }
                    }
                }
            });
        }
    });

    // Forward Internet relay incoming stream
    let tx_relay = stream_tx.clone();
    let relay_addr = get_relay_address(relay_override);
    let relay_token = keys.transit_token();
    let relay_task = tokio::spawn(async move {
        loop {
            match connect_relay(&relay_addr, &relay_token).await {
                Ok(tcp_stream) => {
                    let conn = StreamConnection::Tcp(tcp_stream);
                    let _ = tx_relay.send(("Internet relay".to_string(), conn)).await;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });

    // 3. Connect stream to sender
    println!("{}", style("Waiting for peer connection...").dim());

    let timeout_duration = Duration::from_secs(120);
    let start_time = std::time::Instant::now();
    let mut connection_opt = None;

    while start_time.elapsed() < timeout_duration {
        tokio::select! {
            Some((source, stream)) = stream_rx.recv() => {
                connection_opt = Some((source, stream));
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }

    let (source, mut stream) = match connection_opt {
        Some(s) => s,
        None => {
            swarm_handle.abort();
            lan_task.abort();
            relay_task.abort();
            return Err("Timed out waiting for peer connection. Ensure the transfer code matches and the sender is running.".into());
        }
    };

    println!("{} Connected to peer via {}", style("✔").green().bold(), style(&source).cyan());
    println!("{}", style("Performing zero-knowledge cryptographic handshake...").dim());

    // 4. Handshake: Receiver sends challenge (direction 1, frame 0)
    let mut receiver_challenge = [0u8; 32];
    rand::fill(&mut receiver_challenge);
    let challenge_msg = AuthChallengeMsg {
        version: PROTOCOL_VERSION,
        challenge: receiver_challenge,
    };
    send_json_msg(&mut stream, &keys, 0, 1, &challenge_msg).await?;

    // Receive sender's response (direction 0, frame 0)
    let auth_resp: AuthResponseMsg = recv_json_msg(&mut stream, &keys, 0, 0).await?;
    if !keys.verify_auth_response(&receiver_challenge, &auth_resp.response) {
        swarm_handle.abort();
        return Err("Peer authentication failed: code mismatch!".into());
    }

    // Send final response to sender's challenge (direction 1, frame 1)
    let final_resp = AuthFinalMsg {
        response: keys.compute_auth_response(&auth_resp.peer_challenge),
    };
    send_json_msg(&mut stream, &keys, 1, 1, &final_resp).await?;
    println!("{} Authentication verified. Code matches!", style("✔").green().bold());

    // 5. Receive transfer metadata (direction 0, frame 1)
    let meta: TransferMeta = recv_json_msg(&mut stream, &keys, 1, 0).await?;

    println!();
    let kind = if meta.is_directory {
        format!("Directory ({} files)", meta.file_count)
    } else {
        "File".to_string()
    };
    println!("  {:<12} {} ({}, {})", style("Incoming:").bold(), style(&meta.name).yellow().bold(), kind, format_bytes(meta.total_bytes));
    println!("  {:<12} {}", style("SHA-256:").bold(), style(&meta.sha256).dim());
    println!();

    // Confirm acceptance
    let accept = if auto_accept {
        true
    } else if io::stdin().is_terminal() {
        print!("  Accept transfer? [Y/n]: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        let bytes_read = io::stdin().read_line(&mut input).unwrap_or(0);
        if bytes_read == 0 {
            // Reached EOF on stdin (e.g. closed pipe or Ctrl+D)
            false
        } else {
            let trimmed = input.trim();
            trimmed.is_empty() || trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
        }
    } else {
        true
    };

    if !accept {
        let decision = ReceiverDecision {
            accepted: false,
            reason: Some("Declined by recipient".into()),
        };
        send_json_msg(&mut stream, &keys, 2, 1, &decision).await?;
        println!("{}", style("Transfer declined.").yellow());
        swarm_handle.abort();
        lan_task.abort();
        relay_task.abort();
        return Ok(());
    }

    let decision = ReceiverDecision {
        accepted: true,
        reason: None,
    };
    send_json_msg(&mut stream, &keys, 2, 1, &decision).await?;

    // 6. Receive and stream to temporary staging file
    let temp_staging = tempfile::NamedTempFile::new()?;
    let temp_path = temp_staging.path().to_path_buf();
    let mut temp_file = temp_staging.reopen()?;

    let pb = if io::stdout().is_terminal() {
        let p = ProgressBar::new(meta.total_bytes);
        p.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        p
    } else {
        ProgressBar::hidden()
    };

    let mut hasher = Sha256::new();
    let mut received_bytes: u64 = 0;
    let mut chunk_index: u64 = 2; // frames 0 and 1 were handshake and metadata

    while received_bytes < meta.total_bytes {
        let chunk = read_encrypted_frame(&mut stream, &keys, chunk_index, 0).await?;
        if chunk.is_empty() {
            swarm_handle.abort();
            return Err("Received empty data frame during transfer".into());
        }
        if received_bytes + chunk.len() as u64 > meta.total_bytes {
            swarm_handle.abort();
            return Err(format!(
                "Sender sent {} bytes exceeding metadata total of {} bytes",
                received_bytes + chunk.len() as u64,
                meta.total_bytes
            )
            .into());
        }
        hasher.update(&chunk);
        temp_file.write_all(&chunk)?;
        received_bytes += chunk.len() as u64;
        pb.inc(chunk.len() as u64);
        chunk_index += 1;
    }
    pb.finish_with_message("Received");
    temp_file.flush()?;
    // Explicitly drop open file handle so Windows allows unpacking and deleting cleanly
    drop(temp_file);

    // Read transfer finish message
    let finish_msg: TransferFinish = recv_json_msg(&mut stream, &keys, chunk_index, 0).await?;

    // 7. Data integrity SHA-256 check
    let calculated_sha256 = hex_encode(&hasher.finalize());
    println!();
    println!("{}", style("Verifying data integrity...").dim());

    if calculated_sha256.eq_ignore_ascii_case(&meta.sha256)
        && calculated_sha256.eq_ignore_ascii_case(&finish_msg.sha256)
    {
        // Integrity check passed! Unpack / save payload to destination
        let final_path = unpack_payload(&temp_path, &meta, &dest_dir)?;

        let ack = TransferAck {
            verified: true,
            message: "Integrity check passed".into(),
        };
        send_json_msg(&mut stream, &keys, 3, 1, &ack).await?;

        println!("{}", style("✔ Data integrity verified! (SHA-256 matches perfectly)").green().bold());
        println!("  {:<12} {}", style("SHA-256:").bold(), style(&calculated_sha256).green());
        println!("  {:<12} {}", style("Saved to:").bold(), style(final_path.display().to_string()).yellow().bold());
    } else {
        let ack = TransferAck {
            verified: false,
            message: format!("Hash mismatch: expected {}, got {}", meta.sha256, calculated_sha256),
        };
        send_json_msg(&mut stream, &keys, 3, 1, &ack).await?;

        println!("{}", style("✖ Data integrity verification FAILED!").red().bold());
        println!("  Expected SHA-256: {}", meta.sha256);
        println!("  Computed SHA-256: {}", calculated_sha256);
        println!("{}", style("Partial file has been deleted for security.").red());
    }

    swarm_handle.abort();
    lan_task.abort();
    relay_task.abort();
    Ok(())
}
