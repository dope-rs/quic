use o3::buffer::{self, hold};

use crate::stream::{outbound, release, send};
use hold::evidence;
use outbound::chunk::{self, prefix};
use send::admit;

/// Affine queue mutation awaiting its budget and mode-selected evidence.
pub(crate) struct Batch<M: release::Mode> {
    budget: outbound::Charge,
    proof: M::Projection,
}

impl<M: release::Mode> Batch<M> {
    pub(crate) fn wire_bytes(wire: usize) -> Self {
        Self {
            budget: outbound::Charge {
                wire_bytes: wire,
                ..outbound::Charge::default()
            },
            proof: M::Projection::default(),
        }
    }

    pub(in crate::stream) fn retire<O: buffer::raw::Segment>(
        &mut self,
        prefix: prefix::Prefix<'_, '_, O>,
    ) {
        prefix.retire::<M>(&mut self.budget, &mut self.proof);
    }

    pub(crate) fn release<O: buffer::raw::Segment>(
        &mut self,
        owner: chunk::Node<O>,
        buffers: &mut outbound::BufferCache,
    ) {
        let (budget, proof) = owner.release::<M>(buffers);
        self.add(budget, proof);
    }

    fn add(&mut self, budget: outbound::Charge, proof: M::Projection) {
        self.budget.wire_bytes += budget.wire_bytes;
        self.budget.resident_bytes += budget.resident_bytes;
        self.budget.segments += budget.segments;
        self.proof = M::merge(self.proof, proof);
    }

    pub(crate) fn commit<E: release::Sink<Mode = M>>(
        self,
        source: admit::Source,
        cause: release::Cause,
        release: impl FnOnce(outbound::Charge),
        evidence: &mut E,
    ) {
        release(self.budget);
        evidence.release(self.proof, source, cause);
    }
}

const _: () = {
    assert!(
        core::mem::size_of::<Batch<evidence::Off>>() == core::mem::size_of::<outbound::Charge>()
    );
    assert!(
        core::mem::size_of::<Batch<evidence::On>>() == 2 * core::mem::size_of::<outbound::Charge>()
    );
};
