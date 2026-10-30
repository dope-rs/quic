use crate::conn::wire::{path::probe, storage};
use o3::depot;

pub(in crate::conn) enum Challenge {}
pub(in crate::conn) enum Response {}

// SAFETY: encoding selected this same initialized challenge in its original
// ready prefix. The packet owner excludes any removal through publication.
unsafe impl depot::raw::Project<probe::Position, Challenge> for &mut probe::State {
    type Output = ();

    unsafe fn project(self, index: probe::Position) {
        let mut entry = unsafe {
            depot::raw::Project::<_, storage::Selected<'_, _, _, true>>::project(
                &mut self.challenges,
                usize::from(index.0),
            )
        };
        entry.get_mut().outstanding = true;
    }
}

// SAFETY: every earlier ready-prefix relocation has updated this retained
// selection. The exclusive packet owner consumes each selected reply once.
unsafe impl depot::raw::Project<probe::Position, Response> for &mut probe::State {
    type Output = Option<probe::Relocated>;

    unsafe fn project(self, index: probe::Position) -> Self::Output {
        let entry = unsafe {
            depot::raw::Project::<_, storage::Selected<'_, _, _, true>>::project(
                &mut self.response_controls,
                usize::from(index.0),
            )
        };
        let moved = entry.relocation().map(|(from, to)| probe::Relocated {
            from: probe::Position(from as u8),
            to: probe::Position(to as u8),
        });
        entry.take();
        moved
    }
}

const _: () = assert!(crate::conn::MAX_PATH_TOKENS <= u8::MAX as usize);
