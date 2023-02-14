use bellman::{
    kate_commitment::{Crs, CrsForMonomialForm},
    plonk::{
        better_better_cs::cs::Circuit,
        better_better_cs::{
            cs::{PlonkConstraintSystemParams, ProvingAssembly, SetupAssembly, TrivialAssembly},
            setup::{Setup, VerificationKey},
            verifier::verify,
        },
        commitments::transcript::keccak_transcript::RollingKeccakTranscript,
    },
    worker::Worker,
    Engine, SynthesisError,
};
use std::fs::File;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub fn prove_and_verify_circuit<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: C,
) -> Result<(), SynthesisError> {
    let worker = Worker::new();
    let assembly = generate_proving_assembly::<_, _, P>(&circuit)?;
    // let assembly = generate_testing_assembly::<_, _, P>(&circuit)?;
    println!("Synthesizing setup");
    let setup = generate_setup_for_circuit::<_, _, P>(&circuit, &worker)?;
    let crs_mons = get_trusted_setup::<E>(setup.n + 1);
    println!("Genereting proof");
    let proof = assembly
        .create_proof::<C, RollingKeccakTranscript<E::Fr>>(&worker, &setup, &crs_mons, None)?;
    println!("Generating verification key");
    let vk = VerificationKey::from_setup(&setup, &worker, &crs_mons)?;
    println!("Verifying a proof");
    let valid = verify::<E, C, RollingKeccakTranscript<E::Fr>>(&vk, &proof, None)?;
    assert!(valid);

    Ok(())
}

use bellman::plonk::better_better_cs::proof::Proof;
use bellman::plonk::commitments::transcript::Transcript;

pub fn prove_and_verify_circuit_for_params<
    E: Engine,
    C: Circuit<E>,
    P: PlonkConstraintSystemParams<E>,
    T: Transcript<E::Fr>,
>(
    circuit: C,
    transcript_params: Option<T::InitializationParameters>,
) -> Result<(Proof<E, C>, VerificationKey<E, C>), SynthesisError> {
    let worker = Worker::new();
    // let assembly = generate_testing_assembly::<_, _, P>(&circuit)?;
    println!("Synthesizing setup");
    let setup = generate_setup_for_circuit::<_, _, P>(&circuit, &worker)?;
    let crs_mons = get_trusted_setup::<E>(setup.n + 1);
    println!("Genereting proof");
    let assembly = generate_proving_assembly::<_, _, P>(&circuit)?;
    let proof =
        assembly.create_proof::<C, T>(&worker, &setup, &crs_mons, transcript_params.clone())?;
    println!("Generating verification key");
    let vk = VerificationKey::from_setup(&setup, &worker, &crs_mons)?;
    println!("Verifying a proof");
    let valid = verify::<E, C, T>(&vk, &proof, transcript_params)?;
    assert!(valid);

    Ok((proof, vk))
}

pub fn create_vk<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: C,
) -> Result<VerificationKey<E, C>, SynthesisError> {
    let worker = Worker::new();
    println!("Synthesizing setup");
    let setup = generate_setup_for_circuit::<_, _, P>(&circuit, &worker)?;
    let crs_mons = get_trusted_setup::<E>(setup.n + 1);
    println!("Generating verification key");
    let vk = VerificationKey::from_setup(&setup, &worker, &crs_mons)?;

    Ok(vk)
}

pub fn create_vk_for_padding_size_log_2<
    E: Engine,
    C: Circuit<E>,
    P: PlonkConstraintSystemParams<E>,
>(
    circuit: C,
    size_log_2: usize,
) -> Result<VerificationKey<E, C>, SynthesisError> {
    let worker = Worker::new();
    println!("Synthesizing setup");
    let setup =
        generate_setup_for_circuit_for_size_log_2::<_, _, P>(&circuit, &worker, size_log_2)?;
    assert_eq!(setup.n + 1, 1 << size_log_2);
    let crs_mons = get_trusted_setup::<E>(setup.n + 1);
    println!("Generating verification key");
    let vk = VerificationKey::from_setup(&setup, &worker, &crs_mons)?;

    Ok(vk)
}

pub fn prove_only_circuit_for_params<
    E: Engine,
    C: Circuit<E>,
    P: PlonkConstraintSystemParams<E>,
    T: Transcript<E::Fr>,
>(
    circuit: C,
    transcript_params: Option<T::InitializationParameters>,
    vk: VerificationKey<E, C>,
    size_log_2: Option<usize>,
) -> Result<(Proof<E, C>, VerificationKey<E, C>), SynthesisError> {
    let worker = Worker::new();
    // let assembly = generate_testing_assembly::<_, _, P>(&circuit)?;
    println!("Synthesizing setup");
    let setup = if let Some(size_log_2) = size_log_2 {
        generate_setup_for_circuit_for_size_log_2::<_, _, P>(&circuit, &worker, size_log_2)?
    } else {
        generate_setup_for_circuit::<_, _, P>(&circuit, &worker)?
    };
    println!("Loading setup");
    let crs_mons = get_trusted_setup::<E>(setup.n + 1);
    println!("Genereting proof");
    let assembly = if let Some(size_log_2) = size_log_2 {
        generate_proving_assembly_for_size_log_2::<_, _, P>(&circuit, size_log_2)?
    } else {
        generate_proving_assembly::<_, _, P>(&circuit)?
    };
    let proof =
        assembly.create_proof::<C, T>(&worker, &setup, &crs_mons, transcript_params.clone())?;
    println!("Verifying a proof");
    let valid = verify::<E, C, T>(&vk, &proof, transcript_params)?;
    assert!(valid);

    Ok((proof, vk))
}

pub fn check_if_satisfied<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: C,
) -> Result<(bool, E::Fr), SynthesisError> {
    // println!("Synthesizing");
    let assembly = generate_testing_assembly::<_, _, P>(&circuit)?;
    // println!("Synthsis is done");
    // println!("Used {} gates", assembly.n());
    // println!("Checking if satisfied");
    let is_satisfied = assembly.is_satisfied();
    assert_eq!(assembly.input_assingments.len(), 1);
    assert_eq!(assembly.num_input_gates, 1);
    let public_input = assembly.input_assingments[0];

    Ok((is_satisfied, public_input))
}

fn generate_setup_for_circuit<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: &C,
    worker: &Worker,
) -> Result<Setup<E, C>, SynthesisError> {
    let mut setup_assembly = SetupAssembly::<E, P, C::MainGate>::new();

    circuit.synthesize(&mut setup_assembly)?;
    setup_assembly.finalize();

    let setup = setup_assembly.create_setup::<C>(&worker)?;

    Ok(setup)
}

fn generate_setup_for_circuit_for_size_log_2<
    E: Engine,
    C: Circuit<E>,
    P: PlonkConstraintSystemParams<E>,
>(
    circuit: &C,
    worker: &Worker,
    size_log_2: usize,
) -> Result<Setup<E, C>, SynthesisError> {
    let mut setup_assembly = SetupAssembly::<E, P, C::MainGate>::new();

    circuit.synthesize(&mut setup_assembly)?;
    setup_assembly.finalize_to_size_log_2(size_log_2);

    let setup = setup_assembly.create_setup::<C>(&worker)?;

    Ok(setup)
}

fn generate_proving_assembly<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: &C,
) -> Result<ProvingAssembly<E, P, C::MainGate>, SynthesisError> {
    let mut assembly = ProvingAssembly::<E, P, C::MainGate>::new();

    circuit.synthesize(&mut assembly)?;
    assembly.finalize();

    Ok(assembly)
}

fn generate_proving_assembly_for_size_log_2<
    E: Engine,
    C: Circuit<E>,
    P: PlonkConstraintSystemParams<E>,
>(
    circuit: &C,
    size_log_2: usize,
) -> Result<ProvingAssembly<E, P, C::MainGate>, SynthesisError> {
    let mut assembly = ProvingAssembly::<E, P, C::MainGate>::new();

    circuit.synthesize(&mut assembly)?;
    assembly.finalize_to_size_log_2(size_log_2);

    Ok(assembly)
}

fn generate_testing_assembly<E: Engine, C: Circuit<E>, P: PlonkConstraintSystemParams<E>>(
    circuit: &C,
) -> Result<TrivialAssembly<E, P, C::MainGate>, SynthesisError> {
    let mut assembly = TrivialAssembly::<E, P, C::MainGate>::new();

    circuit.synthesize(&mut assembly)?;
    assembly.finalize();

    Ok(assembly)
}

pub fn get_trusted_setup<E: Engine>(size: usize) -> Crs<E, CrsForMonomialForm> {
    assert!(size.is_power_of_two());

    let crs_file_str = std::env::var("CRS_FILE").unwrap_or("setup_2^26.key".to_string());
    println!("loading keys from {}", crs_file_str);
    let file = File::open(crs_file_str).expect("File not found");
    let mut crs_mons = Crs::<E, CrsForMonomialForm>::read(file).unwrap();
    Arc::get_mut(&mut crs_mons.g1_bases).unwrap().truncate(size);

    crs_mons
}
