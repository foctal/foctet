//! Repeatable release-gate microbenchmark for sizing guidance.
//!
//! This is not a production example: it uses fixed keys so runs are comparable.

use std::{hint::black_box, time::Instant};

use foctet::{
    archive::{ArchiveOptions, create_archive_from_bytes},
    core::{BodyEnvelopeLimits, open_body_with_context, seal_body_with_context},
};
use x25519_dalek::{PublicKey, StaticSecret};

const MIB: f64 = 1024.0 * 1024.0;

fn main() {
    let recipient_secret = StaticSecret::from([0x51; 32]);
    let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
    let payload = vec![0xA5; 1024 * 1024];
    let context = b"foctet release benchmark v1";
    let limits = BodyEnvelopeLimits::default();

    let iterations = 32;
    let started = Instant::now();
    let mut last = Vec::new();
    for _ in 0..iterations {
        last = seal_body_with_context(
            black_box(&payload),
            recipient_public,
            b"benchmark-recipient",
            context,
            &limits,
        )
        .expect("seal benchmark body");
    }
    report(
        "body_seal",
        payload.len() * iterations,
        iterations,
        started.elapsed(),
    );

    let started = Instant::now();
    for _ in 0..iterations {
        let opened = open_body_with_context(
            black_box(&last),
            recipient_secret.to_bytes(),
            context,
            &limits,
        )
        .expect("open benchmark body");
        black_box(opened);
    }
    report(
        "body_open",
        payload.len() * iterations,
        iterations,
        started.elapsed(),
    );

    let archive_iterations = 8;
    let started = Instant::now();
    for _ in 0..archive_iterations {
        let archive = create_archive_from_bytes(
            black_box(&payload),
            &[recipient_public],
            ArchiveOptions::default(),
        )
        .expect("build benchmark archive");
        black_box(archive);
    }
    report(
        "archive_build",
        payload.len() * archive_iterations,
        archive_iterations,
        started.elapsed(),
    );
}

fn report(name: &str, bytes: usize, operations: usize, elapsed: std::time::Duration) {
    let seconds = elapsed.as_secs_f64();
    println!(
        "{{\"case\":\"{name}\",\"operations\":{operations},\"seconds\":{seconds:.6},\"mib_per_second\":{:.2},\"mean_milliseconds\":{:.3}}}",
        bytes as f64 / MIB / seconds,
        seconds * 1000.0 / operations as f64,
    );
}
