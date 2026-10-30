use o3::depot::queue::indexed::planes::resident;

/// One installed value retained by its exclusive registry scope.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(in crate::runtime) struct Key<'id>(pub(super) resident::Key<'id>);
