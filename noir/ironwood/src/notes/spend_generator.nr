use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
pub fn generator() -> Pallas {
    comptime {
        Pallas::from_coordinates(
            Fq::from_limbs([
                659683112944874099227611976510589283,
                185364185338900111643460210172124940,
                14165,
            ]),
            Fq::from_limbs([
                1044077500138915041983506785034320841,
                277785275573207464774291419576990687,
                6864,
            ]),
            false,
        )
    }
}
