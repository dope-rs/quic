#[derive(Debug)]
pub(in crate::conn) enum Error<E> {
    Full,
    Preparation(E),
}
