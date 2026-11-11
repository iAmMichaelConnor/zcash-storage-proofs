use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
pub fn generator() -> Pallas {
    comptime {
        Pallas::from_coordinates(
            Fq::from_limbs([
                657831021341756359098404969875229301,
                883149090579924760524043461866409822,
                9703,
            ]),
            Fq::from_limbs([
                1166413389501258065256410287920120268,
                163660910361144547396870991589111135,
                5468,
            ]),
            false,
        )
    }
}
