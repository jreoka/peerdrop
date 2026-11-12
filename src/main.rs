mod archive;
mod cli;
mod crypto;
mod network;
mod protocol;
mod relay;
mod transfer;
mod words;

use clap::Parser;
use cli::{Cli, Commands};
use console::style;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn looks_like_file_path(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.starts_with("vh1_") || trimmed.contains('@') {
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
        Some(Commands::Send { path, code }) => {
            transfer::run_sender(&path, code, cli.relay.as_deref()).await
        }
        Some(Commands::Receive { code, out, yes }) => {
            transfer::run_receiver(&code, out, yes || cli.yes, cli.relay.as_deref()).await
        }
        Some(Commands::Relay { port, bind }) => {
            relay::run_relay(&bind, port).await
        }
        None => {
            if let Some(target) = cli.target {
                let target_path = PathBuf::from(&target);
                if target_path.exists() {
                    transfer::run_sender(&target_path, cli.custom_code, cli.relay.as_deref()).await
                } else if cli.custom_code.is_some() || looks_like_file_path(&target) {
                    eprintln!(
                        "{} Path '{}' does not exist.",
                        style("Error:").red().bold(),
                        target_path.display()
                    );
                    return ExitCode::from(1);
                } else {
                    transfer::run_receiver(&target, None, cli.yes, cli.relay.as_deref()).await
                }
            } else {
                eprintln!(
                    "{}",
                    style("VoidHop: Encrypted File Transfer")
                        .cyan()
                        .bold()
                );
                eprintln!();
                eprintln!("Usage:");
                eprintln!("  voidhop send <file_or_dir>        Send a file or directory");
                eprintln!("  voidhop receive <code>            Receive using transfer code");
                eprintln!("  voidhop relay                     Run a transit relay server");
                eprintln!();
                eprintln!("Quick Shortcuts:");
                eprintln!("  voidhop <file_or_dir>             Automatically sends the file/dir");
                eprintln!("  voidhop <code>                    Automatically receives with code");
                eprintln!();
                eprintln!("Try 'voidhop --help' for details.");
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
