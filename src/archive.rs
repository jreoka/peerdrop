use crate::crypto::hex_encode;
use crate::protocol::TransferMeta;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

pub struct PreparedPayload {
    pub meta: TransferMeta,
    pub file: File,
    pub _temp_file: Option<tempfile::NamedTempFile>,
}

/// Sanitizes a file or directory name across Windows and Unix platforms.
/// Rejects directory traversal, null bytes, illegal characters, and Windows reserved device names.
pub fn sanitize_file_name(name: &str) -> io::Result<String> {
    let trimmed = name.trim().trim_matches('\0');
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Payload name cannot be empty",
        ));
    }

    // Normalize path separators: replace Windows '\' with '/'
    let normalized = trimmed.replace('\\', "/");
    let base = normalized
        .split('/')
        .rfind(|segment| !segment.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Payload name contains only path separators",
            )
        })?;

    if base == "." || base == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Payload name cannot be '.' or '..'",
        ));
    }

    // Check for illegal characters on Windows and Unix (< > : " / \ | ? * and control chars)
    for ch in base.chars() {
        if ch < ' ' || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Payload name contains illegal character: {:?}", ch),
            ));
        }
    }

    // Check for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    let stem = base.split('.').next().unwrap_or(base);
    let reserved = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
        "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if reserved.contains(&stem.to_ascii_lowercase().as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Payload name '{}' is a reserved system device name", base),
        ));
    }

    Ok(base.to_string())
}

/// Reads all data from a reader, calculating SHA-256 and total bytes read.
fn hash_and_measure<R: Read>(reader: &mut R) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }
    Ok((hex_encode(&hasher.finalize()), total_bytes))
}

pub fn prepare_payload(source_path: &Path) -> io::Result<PreparedPayload> {
    if !source_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Path '{}' does not exist", source_path.display()),
        ));
    }

    let canonical = source_path.canonicalize().unwrap_or_else(|_| source_path.to_path_buf());
    let raw_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("transfer");

    let name = sanitize_file_name(raw_name).unwrap_or_else(|_| "transfer".to_string());

    if source_path.is_file() {
        let mut file = File::open(source_path)?;
        let (sha256, total_bytes) = hash_and_measure(&mut file)?;
        file.seek(SeekFrom::Start(0))?;

        let meta = TransferMeta {
            name,
            is_directory: false,
            total_bytes,
            file_count: 1,
            sha256,
        };

        Ok(PreparedPayload {
            meta,
            file,
            _temp_file: None,
        })
    } else if source_path.is_dir() {
        let mut file_count = 0;
        for entry in WalkDir::new(source_path) {
            let entry = entry.map_err(io::Error::other)?;
            if entry.file_type().is_file() {
                file_count += 1;
            }
        }

        // Create temporary tar archive
        let temp_archive = tempfile::NamedTempFile::new()?;
        {
            let mut tar_builder = tar::Builder::new(&temp_archive);
            // Append directory recursively with base name
            tar_builder.append_dir_all(&name, source_path)?;
            tar_builder.finish()?;
        }

        let mut archive_file = temp_archive.reopen()?;
        let (sha256, total_bytes) = hash_and_measure(&mut archive_file)?;
        archive_file.seek(SeekFrom::Start(0))?;

        let meta = TransferMeta {
            name,
            is_directory: true,
            total_bytes,
            file_count,
            sha256,
        };

        Ok(PreparedPayload {
            meta,
            file: archive_file,
            _temp_file: Some(temp_archive),
        })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path is neither a regular file nor a directory",
        ))
    }
}

/// Safely unpacks a tar archive verifying path containment and rejecting symlinks/tar slip attacks.
pub fn safe_unpack_archive<R: Read>(
    mut archive: tar::Archive<R>,
    dest_dir: &Path,
    expected_root: &str,
) -> io::Result<()> {
    fs::create_dir_all(dest_dir)?;
    let canonical_dest = dest_dir.canonicalize()?;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();

        // 1. Verify path components: disallow prefix, root dir, and parent dir (..)
        let mut first = true;
        for comp in path.components() {
            match comp {
                Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Malicious path traversal detected in archive entry: {:?}", path),
                    ));
                }
                Component::Normal(c) => {
                    let c_str = c.to_string_lossy();
                    if first {
                        first = false;
                        if c_str != expected_root {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "Archive entry '{:?}' escapes root folder '{}'",
                                    path, expected_root
                                ),
                            ));
                        }
                    }
                    if let Err(e) = sanitize_file_name(&c_str) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Invalid archive path component '{}': {}", c_str, e),
                        ));
                    }
                }
                Component::CurDir => {}
            }
        }

        // 2. Reject symlinks, hardlinks, and special device files (prevents symlink-based escape CVEs)
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Symlinks and hardlinks in archives are rejected for security: {:?}",
                    path
                ),
            ));
        }

        if !entry_type.is_dir() && !entry_type.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported archive entry type {:?} for {:?}", entry_type, path),
            ));
        }

        // 3. Unpack entry safely
        entry.unpack_in(&canonical_dest)?;
    }

    Ok(())
}

/// Unpacks a received temporary payload to target destination
pub fn unpack_payload(
    temp_file_path: &Path,
    meta: &TransferMeta,
    dest_dir: &Path,
) -> io::Result<PathBuf> {
    let clean_name = sanitize_file_name(&meta.name)?;
    fs::create_dir_all(dest_dir)?;
    let final_dest = dest_dir.join(&clean_name);

    if meta.is_directory {
        if final_dest.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Cannot extract directory: destination '{}' already exists and is a file",
                    final_dest.display()
                ),
            ));
        }

        let file = File::open(temp_file_path)?;
        let archive = tar::Archive::new(file);
        safe_unpack_archive(archive, dest_dir, &clean_name)?;
        Ok(final_dest)
    } else {
        if final_dest.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Cannot save file: destination '{}' already exists and is a directory",
                    final_dest.display()
                ),
            ));
        }

        if final_dest.exists() {
            fs::remove_file(&final_dest)?;
        }
        fs::copy(temp_file_path, &final_dest)?;
        Ok(final_dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_file_name_valid() {
        assert_eq!(sanitize_file_name("photo.jpg").unwrap(), "photo.jpg");
        assert_eq!(sanitize_file_name("my_documents").unwrap(), "my_documents");
        assert_eq!(sanitize_file_name("file-v1.0.tar.gz").unwrap(), "file-v1.0.tar.gz");
    }

    #[test]
    fn test_sanitize_file_name_strips_paths() {
        assert_eq!(sanitize_file_name("/home/user/test.txt").unwrap(), "test.txt");
        assert_eq!(sanitize_file_name(r"C:\Windows\System32\cmd.exe").unwrap(), "cmd.exe");
        assert_eq!(sanitize_file_name("../../../secret.key").unwrap(), "secret.key");
    }

    #[test]
    fn test_sanitize_file_name_rejects_dangerous_inputs() {
        assert!(sanitize_file_name("").is_err());
        assert!(sanitize_file_name("   ").is_err());
        assert!(sanitize_file_name(".").is_err());
        assert!(sanitize_file_name("..").is_err());
        assert!(sanitize_file_name("/").is_err());
        assert!(sanitize_file_name(r"\").is_err());
        assert!(sanitize_file_name("CON").is_err());
        assert!(sanitize_file_name("aux.txt").is_err());
        assert!(sanitize_file_name("nul").is_err());
        assert!(sanitize_file_name("COM1").is_err());
        assert!(sanitize_file_name("file:stream").is_err());
        assert!(sanitize_file_name("file*name").is_err());
        assert!(sanitize_file_name("file?name").is_err());
    }

    #[test]
    fn test_prepare_payload_single_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("sample.txt");
        fs::write(&file_path, b"Hello PeerDrop test").unwrap();

        let payload = prepare_payload(&file_path).unwrap();
        assert_eq!(payload.meta.name, "sample.txt");
        assert!(!payload.meta.is_directory);
        assert_eq!(payload.meta.total_bytes, 19);
        assert_eq!(payload.meta.file_count, 1);
        assert!(!payload.meta.sha256.is_empty());
    }

    #[test]
    fn test_prepare_and_unpack_directory() {
        let src_dir = tempdir().unwrap();
        let folder = src_dir.path().join("test_folder");
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("f1.txt"), b"File 1 content").unwrap();
        fs::write(folder.join("f2.txt"), b"File 2 content").unwrap();

        let payload = prepare_payload(&folder).unwrap();
        assert_eq!(payload.meta.name, "test_folder");
        assert!(payload.meta.is_directory);
        assert_eq!(payload.meta.file_count, 2);

        // Now test unpack
        let dest_dir = tempdir().unwrap();
        let temp_archive_path = payload._temp_file.as_ref().unwrap().path();
        let final_path = unpack_payload(temp_archive_path, &payload.meta, dest_dir.path()).unwrap();

        assert_eq!(final_path, dest_dir.path().join("test_folder"));
        assert!(final_path.is_dir());
        assert_eq!(fs::read(final_path.join("f1.txt")).unwrap(), b"File 1 content");
        assert_eq!(fs::read(final_path.join("f2.txt")).unwrap(), b"File 2 content");
    }

    #[test]
    fn test_safe_unpack_rejects_symlink() {
        let dest_dir = tempdir().unwrap();

        let temp_tar = tempfile::NamedTempFile::new().unwrap();
        {
            let mut builder = tar::Builder::new(&temp_tar);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("../outside.txt").unwrap();
            header.set_cksum();
            builder.append_data(&mut header, "test_dir/symlink", io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let file = File::open(temp_tar.path()).unwrap();
        let archive = tar::Archive::new(file);
        let res = safe_unpack_archive(archive, dest_dir.path(), "test_dir");
        assert!(res.is_err());
    }

    #[test]
    fn test_safe_unpack_rejects_tar_slip_raw_header() {
        let dest_dir = tempdir().unwrap();

        // Build raw tar with path "test_dir/../outside.txt"
        let mut header = [0u8; 512];
        let name = b"test_dir/../outside.txt";
        header[..name.len()].copy_from_slice(name);
        header[100..108].copy_from_slice(b"0000644\0"); // mode
        header[108..116].copy_from_slice(b"0000000\0"); // uid
        header[116..124].copy_from_slice(b"0000000\0"); // gid
        header[124..136].copy_from_slice(b"00000000005\0"); // size: 5 bytes
        header[136..148].copy_from_slice(b"00000000000\0"); // mtime
        header[148..156].copy_from_slice(b"        "); // chksum spaces
        header[156] = b'0'; // regular file
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        let chksum_str = format!("{:06o}\0 ", sum);
        header[148..156].copy_from_slice(chksum_str.as_bytes());

        let mut temp_tar = tempfile::NamedTempFile::new().unwrap();
        temp_tar.write_all(&header).unwrap();
        let mut data = [0u8; 512];
        data[..5].copy_from_slice(b"hello");
        temp_tar.write_all(&data).unwrap();
        // End of archive (two 512-byte zero blocks)
        temp_tar.write_all(&[0u8; 1024]).unwrap();
        temp_tar.flush().unwrap();

        let file = File::open(temp_tar.path()).unwrap();
        let archive = tar::Archive::new(file);
        let res = safe_unpack_archive(archive, dest_dir.path(), "test_dir");
        assert!(res.is_err());
    }

    #[test]
    fn test_safe_unpack_rejects_mismatched_root() {
        let dest_dir = tempdir().unwrap();

        // Create tar with root "other_dir" when expected is "test_dir"
        let temp_tar = tempfile::NamedTempFile::new().unwrap();
        {
            let mut builder = tar::Builder::new(&temp_tar);
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_cksum();
            header.set_entry_type(tar::EntryType::Regular);
            builder.append_data(&mut header, "other_dir/file.txt", b"test".as_slice()).unwrap();
            builder.finish().unwrap();
        }

        let file = File::open(temp_tar.path()).unwrap();
        let archive = tar::Archive::new(file);
        let res = safe_unpack_archive(archive, dest_dir.path(), "test_dir");
        assert!(res.is_err());
    }
}