use super::poly::Poly;
use bls12_381::*;
use rand::Rng;

/// KZG polinomial commitments on Bls12-381. This structure contains the trusted setup.
pub type Proof = G1Projective;
pub type Commitment = G1Projective;

#[derive(Debug)]
pub struct KZG {
    pub pow_tau_g1: Vec<G1Projective>,
    pub pow_tau_g2: Vec<G2Projective>,
}

impl KZG {
    /// The `n` parameter is the maximum number of points that can be proved
    pub fn setup(n: usize) -> Self {
        let mut rng = rand::thread_rng();
        let rnd: [u64; 4] = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
        let tau = Scalar::from_raw(rnd);

        let pow_tau_g1: Vec<G1Projective> = (0..n)
            .into_iter()
            .scan(Scalar::one(), |acc, _| {
                let v = *acc;
                *acc *= tau;
                Some(v)
            })
            .map(|tau_pow| G1Affine::generator() * tau_pow)
            .collect();

        let pow_tau_g2: Vec<G2Projective> = (0..n)
            .into_iter()
            .scan(Scalar::one(), |acc, _| {
                let v = *acc;
                *acc *= tau;
                Some(v)
            })
            .map(|tau_pow| G2Affine::generator() * tau_pow)
            .collect();

        Self {
            pow_tau_g1,
            pow_tau_g2,
        }
    }

    pub fn prove(&self, poly: &Poly, points: &[(Scalar, Scalar)]) -> Proof {
        let i = Poly::lagrange(points);
        let z = Self::z_poly_of(points);

        let mut poly = poly.clone();
        poly -= &i;
        let (q, remainder) = poly / z;
        assert!(remainder.is_zero());

        self.eval_at_tau_g1(&q)
    }

    pub fn verify(
        &self,
        commitment: &G1Projective,
        points: &[(Scalar, Scalar)],
        proof: &G1Projective,
    ) -> bool {
        let i = Poly::lagrange(points);
        let z = Self::z_poly_of(points);

        let e1 = pairing(&proof.into(), &self.eval_at_tau_g2(&z).into());

        let e2 = pairing(
            &(commitment - self.eval_at_tau_g1(&i)).into(),
            &G2Affine::generator(),
        );
        e1 == e2
    }

    fn z_poly_of(points: &[(Scalar, Scalar)]) -> Poly {
        points.iter().fold(Poly::one(), |acc, (z, _y)| {
            &acc * &Poly::new(vec![-z, Scalar::one()])
        })
    }

    fn eval_at_tau_g1(&self, poly: &Poly) -> G1Projective {
        poly.0
            .iter()
            .enumerate()
            .fold(G1Projective::identity(), |acc, (n, k)| {
                acc + self.pow_tau_g1[n] * k
            })
    }

    fn eval_at_tau_g2(&self, poly: &Poly) -> G2Projective {
        poly.0
            .iter()
            .enumerate()
            .fold(G2Projective::identity(), |acc, (n, k)| {
                acc + self.pow_tau_g2[n] * k
            })
    }

    pub fn poly_commitment_from_set(&self, set: &[(Scalar, Scalar)]) -> (Poly, Commitment) {
        let poly = Poly::lagrange(set);
        let commitment = self.eval_at_tau_g1(&poly);

        (poly, commitment)
    }
}
