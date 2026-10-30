use std::marker;

pub(in crate::conn::output::journals) struct Head<Tag> {
    pub(in crate::conn::output::journals) index: u16,
    domain: marker::PhantomData<fn(Tag) -> Tag>,
}

impl<Tag> Head<Tag> {
    pub(in crate::conn::output::journals) const fn new() -> Self {
        Self {
            index: u16::MAX,
            domain: marker::PhantomData,
        }
    }
}

const _: () = assert!(size_of::<Head<()>>() == 2);
