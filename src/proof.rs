use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use crate::circuits::babyjub::AltJubChip;

use std::{marker::PhantomData, path::PathBuf};

use crate::circuits::{
    bls::Bls381PairChip,
    bls::Bls381SumChip,
    bn256::Bn256PairChip,
    bn256::Bn256SumChip,
    host::{HostOpChip, HostOpConfig, HostOpSelector},
    merkle::MerkleChip,
    poseidon::PoseidonChip,
};

use circuits_batcher::proof::{CircuitInfo, Prover};
use circuits_batcher::args::HashType::Poseidon;

use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use crate::host::ExternalHostCallEntryTable;

pub const MERKLE_DEPTH: usize = 32;

trait HostCircuit<F: FieldExt>: Clone {
    fn load_shared_operands(&self, layouter: impl Layouter<F>, a: Vec<F>) -> Result<Self, Error>;
    fn filter(&self, layouter: impl Layouter<F>) -> Result<Self, Error>;
}

#[derive(clap::Parser)]
struct ArgOpName {
    #[clap(arg_enum)]
    t: OpType,
}
#[derive(clap::ArgEnum, Clone, Debug)]
pub enum OpType {
    BLS381PAIR,
    BLS381SUM,
    BN256PAIR,
    BN256SUM,
    POSEIDONHASH,
    MERKLE,
    JUBJUBSUM,
}

#[derive(Clone)]
struct HostOpCircuit<F: FieldExt, S: HostOpSelector> {
    shared_operands: Vec<F>,
    shared_opcodes: Vec<F>,
    shared_index: Vec<F>,
    _marker: PhantomData<(F, S)>,
}

impl<F: FieldExt, S: HostOpSelector> Default for HostOpCircuit<F, S> {
    fn default() -> Self {
        HostOpCircuit {
            shared_operands: Vec::<F>::default(),
            shared_opcodes: Vec::<F>::default(),
            shared_index: Vec::<F>::default(),
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
struct HostCircuitConfig<C: Clone> {
    hostconfig: HostOpConfig,
    selectconfig: C,
}

impl<S: HostOpSelector> Circuit<Fr> for HostOpCircuit<Fr, S> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = HostCircuitConfig<S::Config>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        HostCircuitConfig {
            hostconfig: HostOpChip::<Fr, S>::configure(meta),
            selectconfig: S::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let host_op_chip =
            HostOpChip::<Fr, S>::construct(config.hostconfig.clone(), config.selectconfig.clone());
        let all_arg_cells = host_op_chip.assign(
            &mut layouter,
            &self.shared_operands,
            &self.shared_opcodes,
            &self.shared_index,
        )?;
        //all_arg_cells.retain(|x| x.value().is_some());
        let mut selector_chip = S::construct(config.selectconfig);
        println!("arg cell num is: {:?}", all_arg_cells.len());
        selector_chip.synthesize(&all_arg_cells, &mut layouter)?;
        Ok(())
    }
}

pub fn gen_host_proof(
    cache_folder: PathBuf,
    v: ExternalHostCallEntryTable,
    opname: OpType,
) {
    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 22;

    // Prepare the private and public inputs to the circuit!
    let shared_operands = v.0.iter().map(|x| Fr::from(x.value as u64)).collect();
    let shared_opcodes = v.0.iter().map(|x| Fr::from(x.op as u64)).collect();
    let shared_index =
        v.0.iter()
            .enumerate()
            .map(|(i, _)| Fr::from(i as u64))
            .collect();

    // Instantiate the circuit with the private inputs.
    // Given the correct public input, our circuit will verify.
    match opname {
        OpType::BLS381PAIR => {
            let bls381pair_circuit = HostOpCircuit::<Fr, Bls381PairChip<Fr>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, Bls381PairChip<Fr>>> =
                CircuitInfo::new(bls381pair_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::BLS381SUM => {
            let bls381sum_circuit = HostOpCircuit::<Fr, Bls381SumChip<Fr>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, Bls381SumChip<Fr>>> =
                CircuitInfo::new(bls381sum_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::BN256PAIR => {
            let bn256pair_circuit = HostOpCircuit::<Fr, Bn256PairChip<Fr>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, Bn256PairChip<Fr>>> =
                CircuitInfo::new(bn256pair_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::BN256SUM => {
            let bn256sum_circuit = HostOpCircuit::<Fr, Bn256SumChip<Fr>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, Bn256SumChip<Fr>>> =
                CircuitInfo::new(bn256sum_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::POSEIDONHASH => {
            let poseidon_circuit = HostOpCircuit::<Fr, PoseidonChip<Fr, 9, 8>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, PoseidonChip<Fr, 9, 8>>> =
                CircuitInfo::new(poseidon_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::MERKLE => {
            let merkle_circuit = HostOpCircuit::<Fr, MerkleChip<Fr, MERKLE_DEPTH>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, MerkleChip<Fr, MERKLE_DEPTH>>> =
                CircuitInfo::new(merkle_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }
        OpType::JUBJUBSUM => {
            let jubjub_circuit = HostOpCircuit::<Fr, AltJubChip<Fr>> {
                shared_operands,
                shared_opcodes,
                shared_index,
                _marker: PhantomData,
            };
            let prover: CircuitInfo<Bn256, HostOpCircuit<Fr, AltJubChip<Fr>>> =
                CircuitInfo::new(jubjub_circuit, format!("{:?}", opname), vec![], k, Poseidon);
            //prover.mock_proof(k as u32);
            prover.proofloadinfo.save(&cache_folder.as_path());
            prover.create_proof(cache_folder.as_path(), 0);
        }

    };
    println!("Proof generated.");
}
