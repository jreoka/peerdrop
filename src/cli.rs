use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "peerdrop",
    author = "Antigravity Team",
    version = "0.1.0",
    about = "Completely peer-to-peer serverless cross-platform encrypted file & directory transfer tool",
    long_about = "PeerDrop is a serverless, end-to-end encrypted CLI file and directory transfer tool.\nIt uses libp2p for P2P transport, mDNS for local discovery, ChaCha20-Poly1305 encryption, and SHA-256 integrity verification."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Direct single argument: if existing file/dir -> send; otherwise -> receive with code
    #[arg(index = 1)]
    pub target: Option<String>,

    /// Optional custom code when sending via direct argument
    #[arg(index = 2)]
    pub custom_code: Option<String>,

    /// Automatically accept incoming transfer without prompting
    #[arg(short = 'y', long = "yes", global = true)]
    pub yes: bool,

    /// Optional custom relay server (host:port) for Internet transfers
    #[arg(long, global = true)]
    pub relay: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send a file or directory to a peer
    Send {
        /// Path to the file or directory to send
        path: PathBuf,

        /// Optional custom code (e.g. 1234-cosmic-falcon)
        #[arg(short, long)]
        code: Option<String>,
    },

    /// Receive a file or directory using a transfer code or ticket
    Receive {
        /// Transfer code (e.g. 1234-cosmic-falcon) or ticket
        code: String,

        /// Output directory to save the received payload (defaults to current directory)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Automatically accept incoming transfer without prompting
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Run a transit relay server to facilitate Internet file transfers
    Relay {
        /// Port to bind the relay server to
        #[arg(short, long, default_value = "4001")]
        port: u16,

        /// IP address or interface to bind to
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
    },
}
