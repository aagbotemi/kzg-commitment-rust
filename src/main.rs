use bls12_381::Scalar;
use kzg_commitment::kzg::KZG;

fn main() {
    println!("KZG Polynomial Commitment");
    let trusted_setup = KZG::setup(5);
    println!("trusted_setup: {:?}", trusted_setup);
    println!("===========NEXT IS THE PROOF============");

    let set = vec![
        (Scalar::from(1), Scalar::from(2)),
        (Scalar::from(2), Scalar::from(3)),
        (Scalar::from(3), Scalar::from(4)),
        (Scalar::from(4), Scalar::from(57)),
    ];
    let (p, c) = KZG::poly_commitment_from_set(&trusted_setup, &set);
    println!("poly_commitment_from_set, p: {:?}, c: {:?}", p, c);

    println!("===========NEXT IS THE MAIN PROOF============");
    let proof01 = KZG::prove(&trusted_setup, &p, &vec![set[0].clone(), set[1].clone()]);
    println!("proof01: {:?}", proof01);

    println!("===========NEXT IS THE VERIFY============");
    let success_result = KZG::verify(
        &trusted_setup,
        &c,
        &vec![set[0].clone(), set[1].clone()],
        &proof01,
    );
    assert!(success_result);
    let failed_result_1 = KZG::verify(&trusted_setup, &c, &vec![set[0].clone()], &proof01);
    assert!(!failed_result_1);
    let failed_result_2 = KZG::verify(
        &trusted_setup,
        &c,
        &vec![set[0].clone(), set[2].clone()],
        &proof01,
    );
    assert!(!failed_result_2);

    // prove and verify that the whole set exists in the whole set
    let proof0123 = KZG::prove(&trusted_setup, &p, &set);
    let verify = KZG::verify(&trusted_setup, &c, &set, &proof0123);
    assert!(verify);
}
