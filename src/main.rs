mod archive;
mod cli;
mod crypto;
mod network;
mod protocol;
mod transfer;
mod words;

use clap::Parser;
use cli::{Cli, Commands};
use console::style;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn looks_like_file_path(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.starts_with("pd1_") || trimmed.contains('@') {
        return false;
    }
    if trimmed.starts_with('.')
        || trimmed.starts_with('~')
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return true;
    }
    // Check if it has a file extension like "foo.txt", "doc.pdf", "archive.tar.gz"
    if let Some(ext) = Path::new(trimmed).extension().and_then(|e| e.to_str())
        && !ext.is_empty()
        && ext.len() <= 5
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return true;
    }
    false
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Send { path, code }) => transfer::run_sender(&path, code).await,
        Some(Commands::Receive { code, out, yes }) => {
            transfer::run_receiver(&code, out, yes || cli.yes).await
        }
        None => {
            if let Some(target) = cli.target {
                let target_path = PathBuf::from(&target);
                if target_path.exists() {
                    transfer::run_sender(&target_path, cli.custom_code).await
                } else if cli.custom_code.is_some() || looks_like_file_path(&target) {
                    eprintln!(
                        "{} Path '{}' does not exist.",
                        style("Error:").red().bold(),
                        target_path.display()
                    );
                    return ExitCode::from(1);
                } else {
                    transfer::run_receiver(&target, None, cli.yes).await
                }
            } else {
                eprintln!(
                    "{}",
                    style("PeerDrop: Completely Peer-to-Peer Encrypted Transfer")
                        .cyan()
                        .bold()
                );
                eprintln!();
                eprintln!("Usage:");
                eprintln!("  peerdrop send <file_or_dir>        Send a file or directory");
                eprintln!("  peerdrop receive <code>            Receive using a croc-like code");
                eprintln!();
                eprintln!("Quick Shortcuts:");
                eprintln!("  peerdrop <file_or_dir>             Automatically sends the file/dir");
                eprintln!("  peerdrop <code>                    Automatically receives with code");
                eprintln!();
                eprintln!("Try 'peerdrop --help' for details.");
                return ExitCode::from(1);
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!();
            eprintln!("{} {}", style("Error:").red().bold(), e);
            ExitCode::from(1)
        }
    }
}
