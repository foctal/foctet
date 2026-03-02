use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use foctet::archive::{
    ArchiveOptions, create_archive_from_bytes, create_split_archive_from_bytes,
    decrypt_archive_to_bytes, decrypt_split_archive_to_bytes,
};
use x25519_dalek::{PublicKey, StaticSecret};

fn output_file_name(input: &Path) -> String {
    input
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "input.bin".to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: cargo run -p foctet --example file_archive_roundtrip -- <input_file> <output_dir>"
        );
        std::process::exit(2);
    }

    let input_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    fs::create_dir_all(&out_dir)?;

    let plaintext = fs::read(&input_path)?;
    let recipient_private = StaticSecret::from([0x77; 32]);
    let recipient_public = PublicKey::from(&recipient_private).to_bytes();

    let options = ArchiveOptions {
        chunk_size: 256 * 1024,
        file_name: Some(output_file_name(&input_path)),
        content_type: Some("application/octet-stream".to_string()),
        created_at_unix: Some(1_700_000_123),
    };

    let (single_archive, single_meta) =
        create_archive_from_bytes(&plaintext, &[recipient_public], options.clone())?;
    let single_archive_path = out_dir.join("encrypted.far");
    fs::write(&single_archive_path, &single_archive)?;

    let single_decrypted = decrypt_archive_to_bytes(&single_archive, recipient_private.to_bytes())?;
    let single_decrypted_path = out_dir.join("decrypted.single.bin");
    fs::write(&single_decrypted_path, &single_decrypted)?;

    let split =
        create_split_archive_from_bytes(&plaintext, &[recipient_public], options, 512 * 1024)?;
    let manifest_path = out_dir.join("manifest.far");
    fs::write(&manifest_path, &split.manifest)?;

    for (idx, part) in split.parts.iter().enumerate() {
        let part_path = out_dir.join(format!("data.part{:03}.far", idx));
        fs::write(part_path, part)?;
    }

    let mut part_refs: Vec<&[u8]> = split.parts.iter().map(Vec::as_slice).collect();
    part_refs.reverse();
    let split_decrypted =
        decrypt_split_archive_to_bytes(&split.manifest, &part_refs, recipient_private.to_bytes())?;
    let split_decrypted_path = out_dir.join("decrypted.split.bin");
    fs::write(&split_decrypted_path, &split_decrypted)?;

    if single_decrypted != plaintext || split_decrypted != plaintext {
        return Err("roundtrip mismatch".into());
    }

    println!("wrote: {}", single_archive_path.display());
    println!("wrote: {}", manifest_path.display());
    println!("wrote: {} parts", split.parts.len());
    println!("single archive chunks: {}", single_meta.total_chunks);
    println!("restored: {}", single_decrypted_path.display());
    println!("restored: {}", split_decrypted_path.display());
    println!("archive roundtrip examples completed successfully");

    Ok(())
}
