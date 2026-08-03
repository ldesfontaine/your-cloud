//! Searching for a canary in whatever a process left behind.
//!
//! A canary proof is only as good as the search: reading a whole core file
//! into memory would put the very bytes under test into the searcher's own
//! address space, and scanning chunk by chunk without an overlap would miss a
//! needle straddling two reads. [`file_contains`] streams with an overlap of
//! exactly one byte less than the needle, which is the smallest window that
//! cannot miss it.
//!
//! Shared with `#[path]` between the crash suite that first needed it and the
//! personal access suite, so both mean the same thing by "absent".

#![allow(dead_code)]

use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

/// Streams `path` looking for `needle`, without ever holding the whole file.
pub fn file_contains(path: &Path, needle: &[u8]) -> io::Result<bool> {
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    let mut chunk = [0_u8; 64 * 1024];
    let mut overlap = Vec::with_capacity(needle.len().saturating_sub(1));
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        let mut window = Vec::with_capacity(overlap.len() + read);
        window.extend_from_slice(&overlap);
        window.extend_from_slice(&chunk[..read]);
        if contains_subslice(&window, needle) {
            return Ok(true);
        }
        let retained = needle.len().saturating_sub(1).min(window.len());
        overlap.clear();
        overlap.extend_from_slice(&window[window.len() - retained..]);
    }
}

/// An empty needle is never "found": absence must mean something.
pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
