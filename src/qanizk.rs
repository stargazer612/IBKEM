// use crate::common::*;
// use ark_bls12_381::{G1Projective, G2Projective};
// use ark_ff::{Field, Zero, One, PrimeField};
// use std::collections::hash_map::DefaultHasher;
// use std::hash::{Hash, Hasher};

// #[derive(Debug, Clone)]
// pub struct QANIZKPublicKey {
//     pub a_g2: Vec<G2Projective>,            
//     pub k_a_g2: Vec<Vec<G2Projective>>,     
//     pub b_g1: Vec<G1Projective>,           
//     pub m_k_g1: Vec<Vec<G1Projective>>,    
//     pub kjb_a_g2: Vec<Vec<Vec<G2Projective>>>, 
//     pub b_kjb_g1: Vec<Vec<Vec<G1Projective>>>, 
//     pub k: usize,
//     pub n: usize,
//     pub lambda: usize,
// }

// #[derive(Debug, Clone)]
// pub struct QANIZKSecretKey {
//     pub k_matrix: Matrix,                  
//     pub kjb_matrices: Vec<Vec<Matrix>>,    
// }

// #[derive(Debug, Clone)]
// pub struct QANIZKProof {
//     pub t_g1: Vec<G1Projective>,    
//     pub u_g1: Vec<G1Projective>,      
// }

// pub struct QANIZK {
//     pub k: usize,           
//     pub n: usize,           
//     pub t: usize,           
//     pub lambda: usize,     
//     pub group: GroupCtx,
// }

// impl QANIZK {
//     pub fn new(k: usize, n: usize, t: usize, lambda: usize) -> Self {
//         Self { k, n, t, lambda, group: GroupCtx::bls12_381() }
//     }

//     // pub fn gen_nizk(&self, m_matrix: &Matrix) -> (QANIZKPublicKey, QANIZKSecretKey) {
        
//     // }

//     // pub fn prove(&self, pk: &QANIZKPublicKey, tag: &[u8], c0_g1: &[G1Projective], r: &Vector) -> QANIZKProof {
                
//     // }

//     // pub fn verify(&self, pk: &QANIZKPublicKey, tag: &[u8], c0_g1: &[G1Projective], proof: &QANIZKProof) -> bool {
    
//     // }

//     // pub fn simulate(&self, pk: &QANIZKPublicKey, sk: &QANIZKSecretKey, tag: &[u8], c0_g1: &[G1Projective]) -> QANIZKProof {
    
//     // }
// }