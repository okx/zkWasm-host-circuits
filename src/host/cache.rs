use crate::host::kvpair::MerkleRecord;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

// If maxsize is set to None, the LRU feature is disabled and the cache can grow without bound.
// The LRU feature performs best when maxsize is a power-of-two.
const DEFAULT_CACHE_SIZE: usize = usize::pow(2, 17);

lazy_static::lazy_static! {
    pub static ref MERKLE_CACHE: Mutex<LruCache<Vec<u8>, MerkleRecord>> =
        Mutex::new(LruCache::<Vec<u8>, MerkleRecord>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
        ));
}

use bytes::{BytesMut, BufMut};

pub fn get_cache_key(cname: String, index: u32, hash: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(cname.len()+36);
    buf.put(cname.as_bytes());
    buf.put_u32(index);
    buf.put(hash);
    buf.freeze().to_vec()

    //cname + &index.to_string() + &hex::encode(hash)
}
