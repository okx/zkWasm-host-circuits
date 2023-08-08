use crate::host::kvpair::MerkleRecord;
use crate::host::merkle::MerkleNode;
// use hex::ToHex;
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::Bson;
use mongodb::{
    bson::doc,
    sync::{Client, Collection},
};
use std::collections::HashMap;
use std::sync::Mutex;

const MONGODB_URI: &str = "mongodb://localhost:27017";
pub const DB_NAME: &str = "zkwasmkvpair";
const DEFAULT_COLLECTION_NAME: &str =
    "MERKLEDATA_0000000000000000000000000000000000000000000000000000000000000000";

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

pub fn bytes_to_bson(x: &[u8; 32]) -> Bson {
    Bson::Binary(mongodb::bson::Binary {
        subtype: BinarySubtype::Generic,
        bytes: (*x).into(),
    })
}

pub struct Store {
    // client: Client,
    cache: HashMap<(u32, [u8; 32]), MerkleRecord>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            // client: Client::with_uri_str(MONGODB_URI).expect("Unexpected DB Error"),
            cache: HashMap::new(),
        }
    }

    pub fn get(
        &self,
        index: u32,
        hash: &[u8; 32],
    ) -> Result<Option<MerkleRecord>, mongodb::error::Error> {
        if let Some(record) = self.cache.get(&(index, *hash)) {
            Ok(Some(record.clone()))
        } else {
            // println!("query db hash={}", hash.encode_hex::<String>());
            let collection = get_collection::<MerkleRecord>(
                DB_NAME.to_string(),
                DEFAULT_COLLECTION_NAME.to_string(),
            )?;
            let mut filter = doc! {};
            filter.insert("index", index);
            filter.insert("hash", bytes_to_bson(hash));
            collection.find_one(filter, None)
        }
    }

    pub fn set(&mut self, node: MerkleRecord) {
        self.cache.insert((node.index(), node.hash()), node);
    }

    pub fn commit(&mut self) -> Result<(), mongodb::error::Error> {
        // insert cached records to db
        if self.cache.len() == 0 {
            return Ok(());
        }
        let mut records = Vec::new();
        for (_, record) in self.cache.iter() {
            records.push(record)
        }
        let collection = get_collection::<MerkleRecord>(
            DB_NAME.to_string(),
            DEFAULT_COLLECTION_NAME.to_string(),
        )?;
        collection.insert_many(records, None)?;
        // clear cache
        self.cache.clear();
        Ok(())
    }
}
