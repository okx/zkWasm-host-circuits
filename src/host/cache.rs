use crate::host::mongomerkle::MerkleRecord;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use crate::host::datahash::DataHashRecord;

// If maxsize is set to None, the LRU feature is disabled and the cache can grow without bound.
// The LRU feature performs best when maxsize is a power-of-two.
const DEFAULT_CACHE_SIZE: usize = usize::pow(2, 24);

lazy_static::lazy_static! {
    pub static ref MERKLE_CACHE: Mutex<LruCache<String, MerkleRecord>> =
        Mutex::new(LruCache::<String, MerkleRecord>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
        ));

    pub static ref DATA_CACHE: Mutex<LruCache<[u8; 32], DataHashRecord>> =
    Mutex::new(LruCache::<[u8; 32], DataHashRecord>::new(
        NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
    ));
}

pub fn get_merkle_cache_key(cname: String, index: u64, hash: &[u8; 32]) -> String {
    cname + &index.to_string() + &hex::encode(hash)
}
