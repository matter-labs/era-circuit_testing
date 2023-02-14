use super::*;

use std::marker::PhantomData;

use bellman::plonk::better_better_cs::cs::{
    ArithmeticTerm, Circuit, ConstraintSystem, MainGateTerm, Width4MainGateWithDNext,
};
use bellman::{
    compact_bn256::Bn256,
    plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams,
};
use bellman::{Engine, Field, PrimeField, SynthesisError};
// use rand::{thread_rng, Rand};

#[test]
fn test_naive_circuit_setup_and_sync_prove() {
    let circuit = TestMainGateOnly::<Bn256> {
        _marker: PhantomData,
    };

    prove_and_verify_circuit::<_, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(circuit)
        .unwrap();
}

pub struct TestMainGateOnly<E: Engine> {
    pub _marker: PhantomData<E>,
}

impl<E: Engine> Circuit<E> for TestMainGateOnly<E> {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let log_degree = 4;
        let degree = (1 << (log_degree)) - 1;
        for _ in 0..degree {
            let a_wit = E::Fr::from_str("42").unwrap();
            let b_wit = E::Fr::from_str("43").unwrap();
            let mut c_wit = a_wit;
            c_wit.add_assign(&b_wit);

            let a = cs.alloc(|| Ok(a_wit))?;
            let b = cs.alloc(|| Ok(b_wit))?;
            let c = cs.alloc(|| Ok(c_wit))?;

            let a = ArithmeticTerm::from_variable(a);
            let b = ArithmeticTerm::from_variable(b);
            let c = ArithmeticTerm::from_variable(c);

            let mut term = MainGateTerm::new();
            term.add_assign(a);
            term.add_assign(b);
            term.sub_assign(c);

            cs.allocate_main_gate(term)?;
        }
        Ok(())
    }
}
