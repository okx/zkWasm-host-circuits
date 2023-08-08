use crate::host::datahash::DataHashRecord;
use crate::host::merkle::MerkleNode;
use crate::host::mongomerkle::MerkleRecord;
use mongodb::bson::{spec::BinarySubtype, Bson};
use mongodb::{
    bson::doc,
    sync::{Client, Collection},
};
use std::collections::HashMap;
use std::sync::Mutex;

const MONGODB_URI: &str = "mongodb://localhost:27017";
pub const DB_NAME: &str = "zkwasm-mongo-merkle";
const MERKLE_COLLECTION_NAME: &str =
    "MERKLEDATA_0000000000000000000000000000000000000000000000000000000000000000";
const DATA_COLLECTION_NAME: &str =
    "DATAHASH_0000000000000000000000000000000000000000000000000000000000000000";

lazy_static::lazy_static! {
    pub static ref CLIENT: Client= Client::with_uri_str(MONGODB_URI).expect("Unexpected DB Error");
    pub static ref STORE: Mutex<Store> = Mutex::new(Store::new());
}

pub fn get_collection<T>(
    database: String,
    name: String,
) -> Result<Collection<T>, mongodb::error::Error> {
    let database = CLIENT.database(database.as_str());
    let collection = database.collection::<T>(name.as_str());
    Ok(collection)
}

pub fn u256_to_bson(x: &[u8; 32]) -> Bson {
    Bson::Binary(mongodb::bson::Binary {
        subtype: BinarySubtype::Generic,
        bytes: (*x).into(),
    })
}

pub fn u64_to_bson(x: u64) -> Bson {
    Bson::Binary(mongodb::bson::Binary {
        subtype: BinarySubtype::Generic,
        bytes: x.to_le_bytes().to_vec(),
    })
}

pub struct Store {
    // client: Client,
    merkle_cache: HashMap<(u64, [u8; 32]), MerkleRecord>,
    data_cache: HashMap<[u8; 32], DataHashRecord>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            // client: Client::with_uri_str(MONGODB_URI).expect("Unexpected DB Error"),
            merkle_cache: HashMap::new(),
            data_cache: HashMap::new(),
        }
    }

    pub fn get_merkle_record(
        &self,
        index: u64,
        hash: &[u8; 32],
    ) -> Result<Option<MerkleRecord>, mongodb::error::Error> {
        if let Some(record) = self.merkle_cache.get(&(index, *hash)) {
            Ok(Some(record.clone()))
        } else {
            // println!("query db hash={}", hash.encode_hex::<String>());
            let collection = get_collection::<MerkleRecord>(
                DB_NAME.to_string(),
                MERKLE_COLLECTION_NAME.to_string(),
            )?;
            let mut filter = doc! {};
            filter.insert("index", u64_to_bson(index));
            filter.insert("hash", u256_to_bson(hash));
            collection.find_one(filter, None)
        }
    }

    pub fn set_merkle_record(&mut self, node: MerkleRecord) {
        self.merkle_cache.insert((node.index(), node.hash()), node);
    }

    pub fn get_data_record(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<DataHashRecord>, mongodb::error::Error> {
        if let Some(record) = self.data_cache.get(hash) {
            Ok(Some(record.clone()))
        } else {
            // println!("query db hash={}", hash.encode_hex::<String>());
            let collection = get_collection::<DataHashRecord>(
                DB_NAME.to_string(),
                DATA_COLLECTION_NAME.to_string(),
            )?;

            let mut filter = doc! {};
            filter.insert("hash", u256_to_bson(hash));
            let record = collection.find_one(filter, None);
            record
        }
    }

    pub fn set_data_record(&mut self, node: DataHashRecord) {
        self.data_cache.insert(node.hash, node);
    }

    pub fn commit(&mut self) -> Result<(), mongodb::error::Error> {
        // insert cached records to db
        if self.merkle_cache.len() > 0 {
            let mut records = Vec::new();
            for (_, record) in self.merkle_cache.iter() {
                records.push(record);
            }
            let collection = get_collection::<MerkleRecord>(
                DB_NAME.to_string(),
                MERKLE_COLLECTION_NAME.to_string(),
            )?;
            collection.insert_many(records, None)?;

            self.merkle_cache.clear();
        }

        if self.data_cache.len() > 0 {
            let mut records = Vec::new();
            for (_, record) in self.data_cache.iter() {
                records.push(record);
            }
            let collection = get_collection::<DataHashRecord>(
                DB_NAME.to_string(),
                DATA_COLLECTION_NAME.to_string(),
            )?;
            collection.insert_many(records, None)?;
            self.data_cache.clear();
        }

        Ok(())
    }
}
