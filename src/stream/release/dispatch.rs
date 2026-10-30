use o3::buffer::hold::{self, evidence};

pub trait Dispatch: evidence::Mode {
    fn project(charge: impl FnOnce() -> hold::Charge) -> Self::Projection;

    fn add(proof: &mut Self::Projection, charge: hold::Charge);

    fn merge(left: Self::Projection, right: Self::Projection) -> Self::Projection;
}

impl Dispatch for evidence::Off {
    fn project(_: impl FnOnce() -> hold::Charge) -> Self::Projection {
        evidence::Off
    }

    fn add(proof: &mut Self::Projection, _: hold::Charge) {
        let evidence::Off = *proof;
    }

    fn merge(left: Self::Projection, right: Self::Projection) -> Self::Projection {
        let evidence::Off = left;
        let evidence::Off = right;
        evidence::Off
    }
}

impl Dispatch for evidence::On {
    fn project(charge: impl FnOnce() -> hold::Charge) -> Self::Projection {
        charge()
    }

    fn add(proof: &mut Self::Projection, charge: hold::Charge) {
        *proof = Self::merge(*proof, charge);
    }

    fn merge(left: Self::Projection, right: Self::Projection) -> Self::Projection {
        hold::Charge::from_commit(
            left.logical_bytes + right.logical_bytes,
            left.resident_bytes + right.resident_bytes,
            left.owners + right.owners,
        )
    }
}
