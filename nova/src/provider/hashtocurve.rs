//! Implementation of Shallue-van de Woestijne method for Weierstrass curves from
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#section-6.6.1

// TODO: introduce isogeny for grumpkin and pasta cycles to arkworks and replace this implementation
// with [`ark_ec::hashing::curve_maps::wb::WBMap`].

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, Field, PrimeField, Zero};

fn svdw_map_to_curve<C: SWCurveConfig>(
    u: C::BaseField,
    c: [C::BaseField; 4],
    z: C::BaseField,
) -> Affine<C>
where
    C::BaseField: PrimeField,
{
    #![allow(clippy::assign_op_pattern)]

    assert!(C::COEFF_A.is_zero());
    let is_square = |f: C::BaseField| f.legendre().is_qr();

    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#section-f.1
    //    1. c1 = g(Z)
    let c1 = c[0];
    //    2. c2 = -Z / 2
    let c2 = c[1];
    //    3. c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))     # sgn0(c3) MUST equal 0
    let c3 = c[2];
    //    4. c4 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    let c4 = c[3];

    //    1.  tv1 = u^2
    let mut tv1 = u.square();
    //    2.  tv1 = tv1 * c1
    tv1 = tv1 * c1;
    //    3.  tv2 = 1 + tv1
    let tv2 = C::BaseField::ONE + tv1;
    //    4.  tv1 = 1 - tv1
    tv1 = C::BaseField::ONE - tv1;
    //    5.  tv3 = tv1 * tv2
    let mut tv3 = tv1 * tv2;
    //    6.  tv3 = inv0(tv3)
    tv3 = tv3.inverse().unwrap();
    //    7.  tv4 = u * tv1
    let mut tv4 = u * tv1;
    //    8.  tv4 = tv4 * tv3
    tv4 = tv4 * tv3;
    //    9.  tv4 = tv4 * c3
    tv4 = tv4 * c3;
    //    10.  x1 = c2 - tv4
    let x1 = c2 - tv4;
    //    11. gx1 = x1^2
    let mut gx1 = x1.square();
    //    12. gx1 = gx1 + A
    //    gx1 = gx1 + C::COEFF_A; // a is 0 for used curves.

    //    13. gx1 = gx1 * x1
    gx1 = gx1 * x1;
    //    14. gx1 = gx1 + B
    gx1 = gx1 + C::COEFF_B;

    //    15.  e1 = is_square(gx1)
    let e1 = is_square(gx1);
    //    16.  x2 = c2 + tv4
    let x2 = c2 + tv4;
    //    17. gx2 = x2^2
    let mut gx2 = x2.square();
    //    18. gx2 = gx2 + A
    //    gx2 = gx2 + C::COEFF_A; // a is 0 for used curves.

    //    19. gx2 = gx2 * x2
    gx2 = gx2 * x2;
    //    20. gx2 = gx2 + B
    gx2 = gx2 + C::COEFF_B;
    //    21.  e2 = is_square(gx2) AND NOT e1
    let e2 = is_square(gx2) && !e1;
    //    22.  x3 = tv2^2
    let mut x3 = tv2.square();
    //    23.  x3 = x3 * tv3
    x3 = x3 * tv3;
    //    24.  x3 = x3^2
    x3 = x3.square();
    //    25.  x3 = x3 * c4
    x3 = x3 * c4;
    //    26.  x3 = x3 + Z
    x3 = x3 + z;

    // CMOV requires `subtle`, not supported by arkworks.
    //    27.  x = CMOV(x3, x1, e1)      # x = x1 if gx1 is square, else x = x3
    let mut x = if e1 { x1 } else { x3 };
    //    28.  x = CMOV(x, x2, e2)       # x = x2 if gx2 is square and gx1 is not
    if e2 {
        x = x2;
    }
    //    29.  gx = x^2
    let mut gx = x.square();
    //    30.  gx = gx + A
    //    gx = gx + C::COEFF_A; // a is 0 for used curves.

    //    31.  gx = gx * x
    gx = gx * x;
    //    32.  gx = gx + B
    gx = gx + C::COEFF_B;
    //    33.   y = sqrt(gx)
    let mut y = gx.sqrt().unwrap();
    //    34.  e3 = sgn0(u) == sgn0(y)
    let e3 = sgn0(u) == sgn0(y);
    //    35. y = CMOV(-y, y, e3)       # Select correct sign of y
    if !e3 {
        y = -y;
    }

    let point = Affine::new_unchecked(x, y);
    debug_assert!(point.is_on_curve());
    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    point
}

pub trait SVDWMap: SWCurveConfig
where
    Self::BaseField: PrimeField,
{
    const Z: Self::BaseField;
    const C: [Self::BaseField; 4];

    fn map_to_curve(u: Self::BaseField) -> Affine<Self> {
        svdw_map_to_curve(u, Self::C, Self::Z)
    }
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#name-the-sgn0-function-2
// sgn0_m_eq_1(x)
//
// Input: x, an element of GF(p).
// Output: 0 or 1.
//
// Steps:
// 1. return x mod 2
//
fn sgn0<F: PrimeField>(x: F) -> u8 {
    x.into_bigint().is_odd() as u8
}

#[allow(unused)]
fn svdw_precomputed_constants<C: SWCurveConfig>(z: C::BaseField) -> [C::BaseField; 4]
where
    C::BaseField: PrimeField,
{
    let a = dbg!(C::COEFF_A);
    let b = dbg!(C::COEFF_B);

    let three = C::BaseField::from(3);
    let four = C::BaseField::from(4);
    let tmp = three * z.square() + four * a;

    // 1. c1 = g(Z)
    let c1 = (z.square() + a) * z + b;
    // 2. c2 = -Z / 2
    let c2 = -z * C::BaseField::from(2).inverse().expect("2 != 0");
    // 3. c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))    # sgn0(c3) MUST equal 0
    let mut c3 = (-c1 * tmp).sqrt().unwrap();
    if c3.into_bigint().is_odd() {
        c3 = -c3;
    }
    debug_assert!(sgn0(c3) == 0);
    // 4. c4 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    let c4 = -four * c1 * tmp.inverse().unwrap();

    [c1, c2, c3, c4]
}

mod curves {
    use super::SVDWMap;
    use ark_ff::{Field, MontFp};

    impl SVDWMap for ark_bn254::g1::Config {
        const Z: ark_bn254::Fq = ark_bn254::Fq::ONE;

        const C: [Self::BaseField; 4] = [
            MontFp!("4"),
            MontFp!(
                "10944121435919637611123202872628637544348155578648911831344518947322613104291"
            ),
            MontFp!("8815841940592487685674414971303048083897117035520822607866"),
            MontFp!("7296080957279758407415468581752425029565437052432607887563012631548408736189"),
        ];
    }

    impl SVDWMap for ark_grumpkin::GrumpkinConfig {
        const Z: ark_grumpkin::Fq = ark_grumpkin::Fq::ONE;

        const C: [Self::BaseField; 4] = [
            MontFp!(
                "21888242871839275222246405745257275088548364400416034343698204186575808495601"
            ),
            MontFp!(
                "10944121435919637611123202872628637544274182200208017171849102093287904247808"
            ),
            MontFp!("17631683881184975371348829942606096167675058198229016842588"),
            MontFp!(
                "14592161914559516814830937163504850059032242933610689562465469457717205663766"
            ),
        ];
    }

    impl SVDWMap for ark_pallas::PallasConfig {
        const Z: ark_pallas::Fq = ark_pallas::Fq::ONE;

        const C: [Self::BaseField; 4] = [
            MontFp!("6"),
            MontFp!(
                "14474011154664524427946373126085988481681528240970780357977338382174983815168"
            ),
            MontFp!("2859014407485960615765440758474493185282020485858576638943397051971528903034"),
            MontFp!(
                "28948022309329048855892746252171976963363056481941560715954676764349967630329"
            ),
        ];
    }

    impl SVDWMap for ark_vesta::VestaConfig {
        const Z: ark_vesta::Fq = ark_vesta::Fq::ONE;

        const C: [Self::BaseField; 4] = [
            MontFp!("6"),
            MontFp!(
                "14474011154664524427946373126085988481681528240970823689839871374196681474048"
            ),
            MontFp!(
                "22058986881797234787318281584519821686177467010939559888476455170070973936824"
            ),
            MontFp!(
                "28948022309329048855892746252171976963363056481941647379679742748393362948089"
            ),
        ];
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{g1::Config, Fq};
    use ark_std::UniformRand;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn svdw_bn254() {
        // test vectors from https://github.com/Consensys/gnark-crypto/blob/73d59806bf0bd5c0fab56141d23b670a8d8fbdfa/ecc/bn254/hash_vectors_test.go#L29

        // Q0: point{"0xe449b959abbd0e5ab4c873eaeb1ccd887f1d9ad6cd671fd72cb8d77fb651892", "0x29ff1e36867c60374695ee0c298fcbef2af16f8f97ed356fa75e61a797ebb265"},
        // Q1: point{"0x19388d9112a306fba595c3a8c63daa8f04205ad9581f7cf105c63c442d7c6511", "0x182da356478aa7776d1de8377a18b41e933036d0b71ab03f17114e4e673ad6e4"},
        // u0: "0x2f87b81d9d6ef05ad4d249737498cc27e1bd485dca804487844feb3c67c1a9b5", u1: "0x6de2d0d7c0d9c7a5a6c0b74675e7543f5b98186b5dbf831067449000b2b1f8e",
        let u0 = Fq::from_str(
            "21498498956904532351723378912032873852253513037650692457560050969314502748597",
        )
        .unwrap();
        let Q0 = Affine::<Config>::new(
            Fq::from_str(
                "6453599284581821454252898427469570073430843606970728650145294868078481709202",
            )
            .unwrap(),
            Fq::from_str(
                "18995581315822946008285423533984677217009732542182181378734620089887646003813",
            )
            .unwrap(),
        );
        let point0 = Config::map_to_curve(u0);

        let u1 = Fq::from_str(
            "3106428082009635406807032300288584059640244342225966151234406580587112112014",
        )
        .unwrap();
        let Q1 = Affine::<Config>::new(
            Fq::from_str(
                "11407741707599100220112369632304941265828026024296299145123573579681208493329",
            )
            .unwrap(),
            Fq::from_str(
                "10936143794657572576642578819087135925019845836839797797601194413922673415908",
            )
            .unwrap(),
        );
        let point1 = Config::map_to_curve(u1);

        assert_eq!(point0, Q0);
        assert_eq!(point1, Q1);
    }

    #[test]
    fn point_is_on_curve() {
        // should not panic
        let mut rng = ark_std::test_rng();

        let u = ark_bn254::Fq::rand(&mut rng);
        let _ = ark_bn254::g1::Config::map_to_curve(u);

        let u = ark_grumpkin::Fq::rand(&mut rng);
        let _ = ark_grumpkin::GrumpkinConfig::map_to_curve(u);

        let u = ark_pallas::Fq::rand(&mut rng);
        let _ = ark_pallas::PallasConfig::map_to_curve(u);

        let u = ark_vesta::Fq::rand(&mut rng);
        let _ = ark_vesta::VestaConfig::map_to_curve(u);
    }
}
