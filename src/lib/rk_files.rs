// Copyright (C) 2020 SoloKeys
// SPDX-License-Identifier: MIT

// Imported from the https://github.com/solokeys/fido-authenticator/ project

use heapless_bytes::Bytes;
use littlefs2::path::PathBuf;

fn format_hex(data: &[u8], mut buffer: &mut [u8]) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    for byte in data.iter() {
        buffer[0] = HEX_CHARS[(byte >> 4) as usize];
        buffer[1] = HEX_CHARS[(byte & 0xf) as usize];
        buffer = &mut buffer[2..];
    }
}

pub fn rp_rk_dir(rp_id_hash: &Bytes<32>) -> PathBuf {
    // uses only first 8 bytes of hash, which should be "good enough"
    let mut hex = [b'0'; 16];
    format_hex(&rp_id_hash[..8], &mut hex);

    let mut dir = PathBuf::from(b"wcrk");
    dir.push(&PathBuf::from(&hex));

    dir
}

pub fn rk_path(rp_id_hash: &Bytes<32>, credential_id_hash: &Bytes<32>) -> PathBuf {
    let mut path = rp_rk_dir(rp_id_hash);

    let mut hex = [0u8; 16];
    format_hex(&credential_id_hash[..8], &mut hex);
    path.push(&PathBuf::from(&hex));

    path
}
