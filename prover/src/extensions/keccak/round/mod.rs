mod component;
mod constants;
mod constraints;
mod eval;
mod interaction_trace;

pub(crate) mod trace;

pub use self::{component::KeccakRound, constants::LANE_SIZE};

fn keccak_round(a: &mut [u64; 25], rc: u64) {
    // θ step
    // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    // D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    // A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = (0..5).fold(0, |acc, i| acc ^ a[x + i * 5]);
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            a[x + y * 5] ^= d[x];
        }
    }

    // ρ and π steps
    // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + ((2 * x + 3 * y) % 5) * 5] =
                a[x + y * 5].rotate_left(constants::ROTATIONS[x + y * 5] as u32);
        }
    }

    // χ step
    // A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    for x in 0..5 {
        for y in 0..5 {
            a[x + y * 5] = b[x + y * 5] ^ (!b[(x + 1) % 5 + y * 5] & b[(x + 2) % 5 + y * 5]);
        }
    }

    // ι step
    // A[0,0] = A[0,0] xor RC
    a[0] ^= rc;
}

#[cfg(test)]
mod tests {
    use super::constants::RC;
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_keccak_round() {
        let mut rng = ChaCha12Rng::from_seed(Default::default());
        let inputs: Vec<[u64; 25]> =
            std::iter::repeat_with(|| std::array::from_fn(|_idx| rng.next_u64()))
                .take(10)
                .collect();

        for &input in &inputs {
            let mut a = input;
            let mut b = a;
            for &rc in &RC {
                keccak_round(&mut a, rc);
            }
            tiny_keccak::keccakf(&mut b);

            assert_eq!(a, b);
        }
    }
}
