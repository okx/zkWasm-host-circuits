use std::collections::HashMap;
//use super::MONGODB_URI;
use crate::host::merkle::{MerkleError, MerkleErrorCode, MerkleNode, MerkleTree};
use crate::host::poseidon::gen_hasher;
//use ff::PrimeField;
use halo2_proofs::pairing::bn256::Fr;
use lazy_static;
use mongodb::bson::{spec::BinarySubtype, Bson};
use mongodb::options::DropCollectionOptions;
use mongodb::{
    bson::doc,
    sync::{Client, Collection},
};
use serde::{
    de::{Error, Unexpected},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::sync::Mutex;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

fn deserialize_u256_as_binary<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    match Bson::deserialize(deserializer) {
        Ok(Bson::Binary(bytes)) => Ok(bytes.bytes.try_into().unwrap()),
        Ok(..) => Err(Error::invalid_value(Unexpected::Enum, &"Bson::Binary")),
        Err(e) => Err(e),
    }
}

fn serialize_bytes_as_binary<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let binary = Bson::Binary(mongodb::bson::Binary {
        subtype: BinarySubtype::Generic,
        bytes: bytes.into(),
    });
    binary.serialize(serializer)
}

// fn bytes_to_bson(x: &[u8; 32]) -> Bson {
//     Bson::Binary(mongodb::bson::Binary {
//         subtype: BinarySubtype::Generic,
//         bytes: (*x).into(),
//     })
// }


#[derive(Debug)]
pub struct MongoMerkle {
    //client: Client,
    //db: HashMap<String, MerkleRecord>,
    contract_address: [u8; 32],
    root_hash: [u8; 32],
    default_hash: Vec<[u8; 32]>,
}

pub fn get_collection<T>(
    client: &Client,
    database: String,
    name: String,
) -> Result<Collection<T>, mongodb::error::Error> {
    let database = client.database(database.as_str());
    let collection = database.collection::<T>(name.as_str());
    Ok(collection)
}

pub fn drop_collection<T>(
    client: &Client,
    database: String,
    name: String,
) -> Result<(), mongodb::error::Error> {
    let collection = get_collection::<MerkleRecord>(client, database, name)?;
    let options = DropCollectionOptions::builder().build();
    collection.drop(options)
}

impl MongoMerkle {
    fn get_collection_name(&self) -> String {
        format!("MERKLEDATA_{}", hex::encode(&self.contract_address))
    }
    // fn get_db_name() -> String {
    //     return "zkwasmkvpair".to_string();
    // }

    pub fn get_record(
        &self,
        index: u32,
        hash: &[u8; 32],
    ) -> Result<Option<MerkleRecord>, mongodb::error::Error> {
        let cname = self.get_collection_name();
        let s = cname + &index.to_string() + &hex::encode(hash);
        let map = GLOBAL_MAP.lock().unwrap();
        Ok(map.get(&s).cloned())
    }

    /* We always insert new record as there might be uncommitted update to the merkle tree */
    pub fn update_record(&mut self, record: MerkleRecord) -> Result<(), mongodb::error::Error> {
        let cname = self.get_collection_name();
        let s = cname + &record.index.to_string() + &hex::encode(&record.hash);
        let mut map = GLOBAL_MAP.lock().unwrap();
        map.insert(s, record);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MerkleRecord {
    index: u32,
    #[serde(serialize_with = "self::serialize_bytes_as_binary")]
    #[serde(deserialize_with = "self::deserialize_u256_as_binary")]
    hash: [u8; 32],
    #[serde(serialize_with = "self::serialize_bytes_as_binary")]
    #[serde(deserialize_with = "self::deserialize_u256_as_binary")]
    left: [u8; 32],
    #[serde(serialize_with = "self::serialize_bytes_as_binary")]
    #[serde(deserialize_with = "self::deserialize_u256_as_binary")]
    right: [u8; 32],
    #[serde(serialize_with = "self::serialize_bytes_as_binary")]
    #[serde(deserialize_with = "self::deserialize_u256_as_binary")]
    data: [u8; 32],
}

impl MerkleNode<[u8; 32]> for MerkleRecord {
    fn index(&self) -> u32 {
        self.index
    }
    fn hash(&self) -> [u8; 32] {
        self.hash
    }
    fn set(&mut self, data: &Vec<u8>) {
        // let mut hasher = gen_hasher();
        self.data = data.clone().try_into().unwrap();
        // let batchdata = data
        //     .chunks(16)
        //     .into_iter()
        //     .map(|x| {
        //         let mut v = x.clone().to_vec();
        //         v.extend_from_slice(&[0u8; 16]);
        //         let f = v.try_into().unwrap();
        //         Fr::from_repr(f).unwrap()
        //     })
        //     .collect::<Vec<Fr>>();
        // let values: [Fr; 2] = batchdata.try_into().unwrap();
        // hasher.update(&values);
        let mut hasher = SHA256_HASHER.clone();
        hasher.input(data);
        hasher.result(&mut self.hash);
        //self.hash = hasher.squeeze().to_repr();
        println!("update with new hash {:?}", self.hash);
    }
    fn right(&self) -> Option<[u8; 32]> {
        Some(self.right)
    }
    fn left(&self) -> Option<[u8; 32]> {
        Some(self.left)
    }
}

impl MerkleRecord {
    fn new(index: u32) -> Self {
        MerkleRecord {
            index,
            hash: [0; 32],
            data: [0; 32],
            left: [0; 32],
            right: [0; 32],
        }
    }

    pub fn data_as_u64(&self) -> [u64; 4] {
        [
            u64::from_le_bytes(self.data[0..8].try_into().unwrap()),
            u64::from_le_bytes(self.data[8..16].try_into().unwrap()),
            u64::from_le_bytes(self.data[16..24].try_into().unwrap()),
            u64::from_le_bytes(self.data[24..32].try_into().unwrap()),
        ]
    }
}

impl MongoMerkle {
    pub fn height() -> usize {
        return 20;
    }
    fn empty_leaf(index: u32) -> MerkleRecord {
        let mut leaf = MerkleRecord::new(index);
        leaf.set(&[0; 32].to_vec());
        leaf
    }
    /// depth start from 0 up to Self::height(). Example 20 height MongoMerkle, root depth=0, leaf depth=20
    fn get_default_hash(&self, depth: usize) -> Result<[u8; 32], MerkleError> {
        if depth <= Self::height() {
            Ok(self.default_hash[Self::height() - depth])
        } else {
            Err(MerkleError::new(
                [0; 32],
                depth as u32,
                MerkleErrorCode::InvalidDepth,
            ))
        }
    }
}

// In default_hash vec, it is from leaf to root.
// For example, height of merkle tree is 20.
// DEFAULT_HASH_VEC[0] leaf's default hash. DEFAULT_HASH_VEC[20] is root default hash. It has 21 layers including the leaf layer and root layer.
lazy_static::lazy_static! {
    static ref DEFAULT_HASH_VEC: Vec<[u8; 32]> = {
        let mut leaf_hash = MongoMerkle::empty_leaf(0).hash;
        let mut default_hash = vec![leaf_hash];
        for _ in 0..(MongoMerkle::height()) {
            leaf_hash = MongoMerkle::hash(&leaf_hash, &leaf_hash);
            default_hash.push(leaf_hash);
        }
        default_hash
    };

    pub static ref POSEIDON_HASHER: poseidon::Poseidon<Fr, 9, 8> = gen_hasher();

    static ref SHA256_HASHER: Sha256 = Sha256::new();

    static ref GLOBAL_MAP: Mutex<HashMap<String, MerkleRecord>> = Mutex::new(HashMap::new());
}

impl MerkleTree<[u8; 32], 20> for MongoMerkle {
    type Id = [u8; 32];
    type Root = [u8; 32];
    type Node = MerkleRecord;

    fn construct(addr: Self::Id, root: Self::Root) -> Self {
        MongoMerkle {
            //client,
            contract_address: addr,
            root_hash: root,
            default_hash: (*DEFAULT_HASH_VEC).clone(),
        }
    }

    fn get_root_hash(&self) -> [u8; 32] {
        self.root_hash
    }

    fn update_root_hash(&mut self, hash: &[u8; 32]) {
        self.root_hash = hash.clone();
    }

    fn hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {

        //let mut hasher = POSEIDON_HASHER.clone();
        let mut hasher = SHA256_HASHER.clone();
        hasher.input(a);
        hasher.input(b);
        let mut result = [0u8; 32];
        hasher.result(&mut result);
        result
        // let a = Fr::from_repr(*a).unwrap();
        // let b = Fr::from_repr(*b).unwrap();
        // hasher.update(&[a, b]);
        // hasher.squeeze().to_repr()
    }

    fn set_parent(
        &mut self,
        index: u32,
        hash: &[u8; 32],
        left: &[u8; 32],
        right: &[u8; 32],
    ) -> Result<(), MerkleError> {
        self.boundary_check(index)?;
        let record = MerkleRecord {
            index,
            data: [0; 32],
            left: *left,
            right: *right,
            hash: *hash,
        };
        //println!("set_node_with_hash {} {:?}", index, hash);
        self.update_record(record).expect("Unexpected DB Error");
        Ok(())
    }

    fn get_node_with_hash(&self, index: u32, hash: &[u8; 32]) -> Result<Self::Node, MerkleError> {
        let v = self.get_record(index, hash).expect("Unexpected DB Error");
        //println!("get_node_with_hash {} {:?} {:?}", index, hash, v);
        let height = (index + 1).ilog2();
        v.map_or(
            {
                let default = self.get_default_hash(height as usize)?;
                let child_hash = if height == Self::height() as u32 {
                    [0; 32]
                } else {
                    self.get_default_hash((height + 1) as usize)?
                };
                if default == *hash {
                    Ok(MerkleRecord {
                        index,
                        hash: self.get_default_hash(height as usize)?,
                        data: [0; 32],
                        left: child_hash,
                        right: child_hash,
                    })
                } else {
                    Err(MerkleError::new(*hash, index, MerkleErrorCode::InvalidHash))
                }
            },
            |x| {
                assert!(x.index == index);
                Ok(x)
            },
        )
    }

    fn set_leaf(&mut self, leaf: &MerkleRecord) -> Result<(), MerkleError> {
        self.boundary_check(leaf.index())?; //should be leaf check?
        self.update_record(leaf.clone())
            .expect("Unexpected DB Error");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use crypto::digest::Digest;
    use super::{MerkleRecord, MongoMerkle, DEFAULT_HASH_VEC};
    use crate::host::{
        kvpair::drop_collection,
        merkle::{MerkleNode, MerkleTree},
    };
    use crate::host::kvpair::POSEIDON_HASHER;
    use ff::PrimeField;
    use halo2_proofs::pairing::bn256::Fr;
    use crate::host::kvpair::SHA256_HASHER;

    #[test]
    fn hash_bench() {
        let a = [0; 32];
        let b = [1; 32];
        MongoMerkle::hash(&a, &b);
        let start = Instant::now();
        for _i in 0..1000 {
            let mut hasher = POSEIDON_HASHER.clone();
            let a = Fr::from_repr(a).unwrap();
            let b = Fr::from_repr(b).unwrap();
            hasher.update(&[a, b]);
            hasher.squeeze().to_repr();
        }
        println!("cost:{:?}", Instant::now().duration_since(start));
    }

    #[test]
    fn sha256_bench() {
        let _hasher = SHA256_HASHER.clone();
        let a = [1u8; 32].to_vec();
        let start = Instant::now();
        for _i in 0..2 {
            let mut hasher = SHA256_HASHER.clone();
            hasher.input(&a);
            let mut result = [0u8; 32];
            hasher.result(&mut result)
        }
        println!("cost:{:?}", Instant::now().duration_since(start));
    }

    use futures::executor;
    use crate::host::poseidon::gen_hasher;

    #[test]
    fn poseidon() {
        let hasher = gen_hasher();
        let start = Instant::now();
        let mut hasher1 = hasher.clone();
        let a = Fr::from_repr([1;32]).unwrap();
        let b = Fr::from_repr([2;32]).unwrap();
        hasher1.update(&[a, b]);
        let result = hasher1.squeeze().to_repr();
        println!("result:{:?}", result);
        println!("cost: {:?}", Instant::now().duration_since(start));
        let start = Instant::now();
        let mut hasher2 = hasher.clone();
        let a = Fr::from_repr([1;32]).unwrap();
        let b = Fr::from_repr([2;32]).unwrap();
        hasher2.update(&[a, b]);
        let result = hasher2.squeeze().to_repr();
        println!("result:{:?}", result);
        println!("cost: {:?}", Instant::now().duration_since(start));
    }

    #[test]
    /* Test for check parent node
     * 1. Clear m tree collection. Create default empty m tree. Check root.
     * 2. Update index=2_u32.pow(20) - 1 (first leaf) leave value.
     * 3. Update index=2_u32.pow(20) (second leaf) leave value.
     * 4. Get index=2_u32.pow(19) - 1 node with hash and confirm the left and right are previous set leaves.
     * 5. Load mt from DB and Get index=2_u32.pow(19) - 1 node with hash and confirm the left and right are previous set leaves.
     */
    fn test_mongo_merkle_parent_node() {
        // Init checking results
        const TEST_ADDR: [u8; 32] = [1; 32];

        const DEFAULT_ROOT_HASH: [u8; 32] = [
            121, 152, 129, 117, 0, 25, 202, 57, 81, 89, 65, 160, 2, 49, 114, 149, 20, 202, 64, 41, 73, 138, 12, 103, 94, 157, 102, 160, 244, 52, 1, 3
        ];

        const DEFAULT_ROOT_HASH64: [u64; 4] = [
            4164168295219566713, 10768723546344610129, 7425461932456462868, 216512482358238558
        ];

        const INDEX1: u32 = 2_u32.pow(20) - 1;
        const LEAF1_DATA: [u8; 32] = [
            0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const ROOT_HASH_AFTER_LEAF1: [u8; 32] = [
            73, 252, 113, 5, 20, 47, 124, 240, 254, 127, 239, 3, 134, 188, 89, 238, 184, 79, 178, 197, 198, 240, 44, 168, 168, 5, 204, 111, 155, 37, 54, 227
        ];
        const ROOT64_HASH_AFTER_LEAF1: [u64; 4] = [
            17328777229252033609, 17174965937731764222, 12118325433858150328, 16372314844877817256
        ];

        const INDEX2: u32 = 2_u32.pow(20);
        const LEAF2_DATA: [u8; 32] = [
            0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        const ROOT_HASH_AFTER_LEAF2: [u8; 32] = [
            247, 80, 129, 60, 148, 253, 22, 190, 56, 25, 27, 211, 111, 111, 99, 232, 28, 13, 147, 143, 248, 183, 20, 254, 166, 217, 249, 214, 24, 90, 110, 1
        ];
        const ROOT64_HASH_AFTER_LEAF2: [u64; 4] = [
            13697414129806037239, 16745350365567457592, 18308460663356460316, 103118904208513446
        ];

        const PARENT_INDEX: u32 = 2_u32.pow(19) - 1;

        // 1
        let mut mt = MongoMerkle::construct(TEST_ADDR, DEFAULT_HASH_VEC[MongoMerkle::height()]);
        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();
        /* */
        assert_eq!(root, DEFAULT_ROOT_HASH);
        assert_eq!(root64, DEFAULT_ROOT_HASH64);

        // 2
        let (mut leaf1, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        leaf1.set(&LEAF1_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf1).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();
        assert_eq!(root, ROOT_HASH_AFTER_LEAF1);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF1);

        // 3
        let (mut leaf2, _) = mt.get_leaf_with_proof(INDEX2).unwrap();
        leaf2.set(&LEAF2_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf2).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();
        assert_eq!(root, ROOT_HASH_AFTER_LEAF2);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF2);

        // 4
        let parent_hash: [u8; 32] = MongoMerkle::hash(&leaf1.hash, &leaf2.hash);
        let parent_node = mt.get_node_with_hash(PARENT_INDEX, &parent_hash).unwrap();
        assert_eq!(leaf1.hash, parent_node.left().unwrap());
        assert_eq!(leaf2.hash, parent_node.right().unwrap());

        // 5
        let a: [u8; 32] = ROOT_HASH_AFTER_LEAF2;
        let mt_loaded: MongoMerkle = MongoMerkle::construct(TEST_ADDR, a);
        assert_eq!(mt_loaded.get_root_hash(), a);
        let (leaf1, _) = mt_loaded.get_leaf_with_proof(INDEX1).unwrap();
        assert_eq!(leaf1.index, INDEX1);
        assert_eq!(leaf1.data, LEAF1_DATA);
        let (leaf2, _) = mt_loaded.get_leaf_with_proof(INDEX2).unwrap();
        assert_eq!(leaf2.index, INDEX2);
        assert_eq!(leaf2.data, LEAF2_DATA);
        let parent_hash: [u8; 32] = MongoMerkle::hash(&leaf1.hash, &leaf2.hash);
        let parent_node = mt_loaded
            .get_node_with_hash(PARENT_INDEX, &parent_hash)
            .unwrap();
        assert_eq!(leaf1.hash, parent_node.left().unwrap());
        assert_eq!(leaf2.hash, parent_node.right().unwrap());
    }

    #[test]
    /* Basic tests for 20 height m tree
     * 1. Clear m tree collection. Create default empty m tree. Check root.
     * 2. Update index=2_u32.pow(20) - 1 (first leaf) leave value. Check root.
     * 3. Check index=2_u32.pow(20) - 1 leave value updated.
     * 4. Load m tree from DB, check root and leave value.
     */
    fn test_mongo_merkle_single_leaf_update() {
        // Init checking results
        const TEST_ADDR: [u8; 32] = [2; 32];

        const DEFAULT_ROOT_HASH: [u8; 32] = [
            121, 152, 129, 117, 0, 25, 202, 57, 81, 89, 65, 160, 2, 49, 114, 149, 20, 202, 64, 41, 73, 138, 12, 103, 94, 157, 102, 160, 244, 52, 1, 3
        ];

        const DEFAULT_ROOT_HASH64: [u64; 4] = [
            4164168295219566713, 10768723546344610129, 7425461932456462868, 216512482358238558
        ];

        const INDEX1: u32 = 2_u32.pow(20) - 1;
        const LEAF1_DATA: [u8; 32] = [
            0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const ROOT_HASH_AFTER_LEAF1: [u8; 32] = [
            73, 252, 113, 5, 20, 47, 124, 240, 254, 127, 239, 3, 134, 188, 89, 238, 184, 79, 178, 197, 198, 240, 44, 168, 168, 5, 204, 111, 155, 37, 54, 227
        ];
        const ROOT64_HASH_AFTER_LEAF1: [u64; 4] = [
            17328777229252033609, 17174965937731764222, 12118325433858150328, 16372314844877817256
        ];

        // 1
        let mut mt = MongoMerkle::construct(TEST_ADDR, DEFAULT_HASH_VEC[MongoMerkle::height()]);
        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();
        assert_eq!(root, DEFAULT_ROOT_HASH);
        assert_eq!(root64, DEFAULT_ROOT_HASH64);

        // 2
        let (mut leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        leaf.set(&LEAF1_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();
        assert_eq!(root, ROOT_HASH_AFTER_LEAF1);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF1);

        // 3
        let (leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        assert_eq!(leaf.index, INDEX1);
        assert_eq!(leaf.data, LEAF1_DATA);

        // 4
        let a = ROOT_HASH_AFTER_LEAF1;
        let mt = MongoMerkle::construct(TEST_ADDR, a);
        assert_eq!(mt.get_root_hash(), a);
        let (leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        assert_eq!(leaf.index, INDEX1);
        assert_eq!(leaf.data, LEAF1_DATA);
    }

    #[test]
    /* Tests for 20 height m tree with updating multple leaves
     * 1. Clear m tree collection. Create default empty m tree. Check root (default one, A).
     * 2. Update index=2_u32.pow(20) - 1 (first leaf) leave value. Check root (1 leave updated, B). Check index=2_u32.pow(20) - 1 leave value updated.
     * 3. Update index=2_u32.pow(20) (second leaf) leave value. Check root (1 leave updated, C). Check index=2_u32.pow(20) leave value updated.
     * 4. Update index=2_u32.pow(21) - 2 (last leaf) leave value. Check root (1 leave updated, D). Check index=2_u32.pow(21) -2 leave value updated.
     * 5. Load m tree from DB with D root hash, check root and leaves' values.
     */
    fn test_mongo_merkle_multi_leaves_update() {
        // Init checking results
        const TEST_ADDR: [u8; 32] = [3; 32];
        const DEFAULT_ROOT_HASH: [u8; 32] = [
            121, 152, 129, 117, 0, 25, 202, 57, 81, 89, 65, 160, 2, 49, 114, 149, 20, 202, 64, 41, 73, 138, 12, 103, 94, 157, 102, 160, 244, 52, 1, 3
        ];

        const DEFAULT_ROOT_HASH64: [u64; 4] = [
            4164168295219566713, 10768723546344610129, 7425461932456462868, 216512482358238558
        ];

        const INDEX1: u32 = 2_u32.pow(20) - 1;
        const LEAF1_DATA: [u8; 32] = [
            0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const ROOT_HASH_AFTER_LEAF1: [u8; 32] = [
            73, 252, 113, 5, 20, 47, 124, 240, 254, 127, 239, 3, 134, 188, 89, 238, 184, 79, 178, 197, 198, 240, 44, 168, 168, 5, 204, 111, 155, 37, 54, 227
        ];
        const ROOT64_HASH_AFTER_LEAF1: [u64; 4] = [
            17328777229252033609, 17174965937731764222, 12118325433858150328, 16372314844877817256
        ];

        const INDEX2: u32 = 2_u32.pow(20);
        const LEAF2_DATA: [u8; 32] = [
            0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        const ROOT_HASH_AFTER_LEAF2: [u8; 32] = [
            247, 80, 129, 60, 148, 253, 22, 190, 56, 25, 27, 211, 111, 111, 99, 232, 28, 13, 147, 143, 248, 183, 20, 254, 166, 217, 249, 214, 24, 90, 110, 1
        ];
        const ROOT64_HASH_AFTER_LEAF2: [u64; 4] = [
            13697414129806037239, 16745350365567457592, 18308460663356460316, 103118904208513446
        ];

        const INDEX3: u32 = 2_u32.pow(21) - 2;
        const LEAF3_DATA: [u8; 32] = [
            18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const ROOT_HASH_AFTER_LEAF3: [u8; 32] = [
            88, 39, 144, 77, 45, 1, 157, 176, 151, 121, 71, 250, 94, 42, 214, 190, 125, 94, 61, 203, 105, 251, 222, 85, 50, 249, 11, 48, 134, 14, 233, 65
        ];
        const ROOT64_HASH_AFTER_LEAF3: [u64; 4] = [
            12726329416105338712, 13751225099636668823, 6187659369853574781, 4749343251533396274
        ];

        // 1
        let mut mt = MongoMerkle::construct(TEST_ADDR, DEFAULT_HASH_VEC[MongoMerkle::height()]);
        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();

        assert_eq!(root, DEFAULT_ROOT_HASH);
        assert_eq!(root64, DEFAULT_ROOT_HASH64);

        // 2
        let (mut leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        leaf.set(&LEAF1_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();

        assert_eq!(root, ROOT_HASH_AFTER_LEAF1);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF1);

        let (leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();

        assert_eq!(leaf.index, INDEX1);
        assert_eq!(leaf.data, LEAF1_DATA);

        // 3
        let (mut leaf, _) = mt.get_leaf_with_proof(INDEX2).unwrap();
        leaf.set(&LEAF2_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();

        assert_eq!(root, ROOT_HASH_AFTER_LEAF2);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF2);

        let (leaf, _) = mt.get_leaf_with_proof(INDEX2).unwrap();
        assert_eq!(leaf.index, INDEX2);
        assert_eq!(leaf.data, LEAF2_DATA);

        // 4
        let (mut leaf, _) = mt.get_leaf_with_proof(INDEX3).unwrap();
        leaf.set(&LEAF3_DATA.to_vec());
        mt.set_leaf_with_proof(&leaf).unwrap();

        let root = mt.get_root_hash();
        let root64 = root
            .chunks(8)
            .into_iter()
            .map(|x| u64::from_le_bytes(x.to_vec().try_into().unwrap()))
            .collect::<Vec<u64>>();

        assert_eq!(root, ROOT_HASH_AFTER_LEAF3);
        assert_eq!(root64, ROOT64_HASH_AFTER_LEAF3);

        let (leaf, _) = mt.get_leaf_with_proof(INDEX3).unwrap();
        assert_eq!(leaf.index, INDEX3);
        assert_eq!(leaf.data, LEAF3_DATA);

        // 5
        let mt = MongoMerkle::construct(TEST_ADDR, ROOT_HASH_AFTER_LEAF3);
        assert_eq!(mt.get_root_hash(), ROOT_HASH_AFTER_LEAF3);
        let (leaf, _) = mt.get_leaf_with_proof(INDEX1).unwrap();
        assert_eq!(leaf.index, INDEX1);
        assert_eq!(leaf.data, LEAF1_DATA);
        let (leaf, _) = mt.get_leaf_with_proof(INDEX2).unwrap();
        assert_eq!(leaf.index, INDEX2);
        assert_eq!(leaf.data, LEAF2_DATA);
        let (leaf, _) = mt.get_leaf_with_proof(INDEX3).unwrap();
        assert_eq!(leaf.index, INDEX3);
        assert_eq!(leaf.data, LEAF3_DATA);
    }
}
