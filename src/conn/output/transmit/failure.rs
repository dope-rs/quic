use crate::conn::output::transmit;

#[derive(Debug)]
pub struct Failure {
    pub effects: transmit::Effects,
    pub error: transmit::Error,
}

const _: () = {
    assert!(size_of::<Failure>() == size_of::<(transmit::Effects, transmit::Error)>());
    assert!(align_of::<Failure>() == align_of::<(transmit::Effects, transmit::Error)>());
};
