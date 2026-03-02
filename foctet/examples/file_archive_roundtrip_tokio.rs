use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
};

use foctet::archive::{
    ArchiveOptions, SplitArchive, create_archive_from_bytes, create_split_archive_from_bytes,
    decrypt_archive_to_bytes, decrypt_split_archive_to_bytes,
};
use tokio::fs;
use x25519_dalek::{PublicKey, StaticSecret};

fn output_file_name(input: &Path) -> String {
    input
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "input.bin".to_string())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: cargo run -p foctet --example file_archive_roundtrip_tokio -- <input_file> <output_dir>"
        );
        std::process::exit(2);
    }

    let input_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);
    fs::create_dir_all(&out_dir).await?;

    let plaintext = fs::read(&input_path).await?;
    let recipient_private = StaticSecret::from([0x77; 32]);
    let recipient_public = PublicKey::from(&recipient_private).to_bytes();

    let options = ArchiveOptions {
        chunk_size: 256 * 1024,
        file_name: Some(output_file_name(&input_path)),
        content_type: Some("application/octet-stream".to_string()),
        created_at_unix: Some(1_700_000_123),
    };

    let plaintext_for_single = plaintext.clone();
    let options_for_single = options.clone();
    let single_out = tokio::task::spawn_blocking(move || {
        create_archive_from_bytes(
            &plaintext_for_single,
            &[recipient_public],
            options_for_single,
        )
    })
    .await
    .map_err(|e| format!("single archive task join error: {e}"))??;

    let (single_archive, single_meta) = single_out;
    let single_archive_path = out_dir.join("encrypted.far");
    fs::write(&single_archive_path, &single_archive).await?;

    let private_key = recipient_private.to_bytes();
    let single_decrypted =
        tokio::task::spawn_blocking(move || decrypt_archive_to_bytes(&single_archive, private_key))
            .await
            .map_err(|e| format!("single decrypt task join error: {e}"))??;

    let single_decrypted_path = out_dir.join("decrypted.single.bin");
    fs::write(&single_decrypted_path, &single_decrypted).await?;

    let plaintext_for_split = plaintext.clone();
    let options_for_split = options.clone();
    let split: SplitArchive = tokio::task::spawn_blocking(move || {
        create_split_archive_from_bytes(
            &plaintext_for_split,
            &[recipient_public],
            options_for_split,
            512 * 1024,
        )
    })
    .await
    .map_err(|e| format!("split archive task join error: {e}"))??;

    let manifest_path = out_dir.join("manifest.far");
    fs::write(&manifest_path, &split.manifest).await?;

    for (idx, part) in split.parts.iter().enumerate() {
        let part_path = out_dir.join(format!("data.part{:03}.far", idx));
        fs::write(part_path, part).await?;
    }

    let split_decrypted = {
        let manifest = split.manifest.clone();
        let parts = split.parts.clone();
        tokio::task::spawn_blocking(move || {
            let mut part_refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            part_refs.reverse();
            decrypt_split_archive_to_bytes(&manifest, &part_refs, recipient_private.to_bytes())
        })
        .await
        .map_err(|e| format!("split decrypt task join error: {e}"))??
    };

    let split_decrypted_path = out_dir.join("decrypted.split.bin");
    fs::write(&split_decrypted_path, &split_decrypted).await?;

    if single_decrypted != plaintext || split_decrypted != plaintext {
        return Err("roundtrip mismatch".into());
    }

    println!("wrote: {}", single_archive_path.display());
    println!("wrote: {}", manifest_path.display());
    println!("wrote: {} parts", split.parts.len());
    println!("single archive chunks: {}", single_meta.total_chunks);
    println!("restored: {}", single_decrypted_path.display());
    println!("restored: {}", split_decrypted_path.display());
    println!("tokio archive roundtrip example completed successfully");

    Ok(())
}
