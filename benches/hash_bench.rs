use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::PrimeField;
use halo2_proofs::pairing::bn256::Fr;
use poseidon::Poseidon;
use poseidon::Spec;
use zkwasm_host_circuits::host::poseidon::POSEIDON_HASHER;

pub fn hash_bench(c: &mut Criterion) {
    c.bench_function("poseidon hash", |b| {
        b.iter(|| {
            let a0 = [0; 32];
            let a1 = [1; 32];
            let a2 = [2; 32];
            let a3 = [3; 32];
            let a4 = [4; 32];
            let a5 = [5; 32];
            let a6 = [6; 32];
            let a7 = [7; 32];

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
        })
    });
}

criterion_group!(benches, hash_bench,);

criterion_main!(benches);
