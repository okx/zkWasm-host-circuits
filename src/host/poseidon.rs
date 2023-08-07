use halo2_proofs::pairing::bn256::Fr;
use poseidon::Poseidon;
use poseidon::Spec;

pub const PREFIX_CHALLENGE: u64 = 0u64;
pub const PREFIX_POINT: u64 = 1u64;
pub const PREFIX_SCALAR: u64 = 2u64;

// We have two hasher here
// 1. MERKLE_HASHER that is used for non sponge hash for hash two merkle siblings
// 2. POSEIDON_HASHER thas is use for poseidon hash of data
lazy_static::lazy_static! {
    pub static ref POSEIDON_HASHER: poseidon::Poseidon<Fr, 9, 8> = Poseidon::<Fr, 9, 8>::new(8, 63);
    pub static ref MERKLE_HASHER: poseidon::Poseidon<Fr, 3, 2> = Poseidon::<Fr, 3, 2>::new(8, 57);
    pub static ref POSEIDON_HASHER_SPEC: poseidon::Spec<Fr, 9, 8> = Spec::new(8, 63);
    pub static ref MERKLE_HASHER_SPEC: poseidon::Spec<Fr, 3, 2> = Spec::new(8, 57);
}

#[cfg(test)]
mod tests {
    use halo2_proofs::pairing::bn256::Fr;
    use crate::host::poseidon::POSEIDON_HASHER;
    use ff::PrimeField;

    #[test]
    fn test_poseidon() {
        const ZERO_HASHER_SQUEEZE: &str =
            "0x03f943aabd67cd7b72a539f3de686c3280c36c572be09f2b9193f5ef78761c6b"; //force the hasher is for fr field result.
        let mut hasher = super::POSEIDON_HASHER.clone();
        hasher.update(&[Fr::zero()]);
        let result = hasher.squeeze();
        println!("hash result is {:?}", result);
        assert_eq!(result.to_string(), ZERO_HASHER_SQUEEZE);
    }

    use std::time::Instant;

    #[test]
    fn hash_bench() {
        let a0 = [0; 32];
        let a1 = [1; 32];
        let a2 = [2; 32];
        let a3 = [3; 32];
        let a4 = [4; 32];
        let a5 = [5; 32];
        let a6 = [6; 32];
        let a7 = [7; 32];
        let _hasher = POSEIDON_HASHER.clone();
        let start = Instant::now();
        for _i in 0..40000 {
            let mut hasher = POSEIDON_HASHER.clone();
            let a0 = Fr::from_repr(a0).unwrap();
            let a1 = Fr::from_repr(a1).unwrap();
            let a2 = Fr::from_repr(a2).unwrap();
            let a3 = Fr::from_repr(a3).unwrap();
            let a4 = Fr::from_repr(a4).unwrap();
            let a5 = Fr::from_repr(a5).unwrap();
            let a6 = Fr::from_repr(a6).unwrap();
            let a7 = Fr::from_repr(a7).unwrap();
            hasher.update(&[a0, a1, a2, a3, a4, a5, a6, a7]);
            hasher.squeeze().to_repr();
        }
        println!("cost:{:?}", Instant::now().duration_since(start));
    }
}
