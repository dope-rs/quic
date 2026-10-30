use std::{marker, mem, num};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub struct Token<'id>(marker::PhantomData<fn(&'id mut ()) -> &'id mut ()>);

impl Token<'_> {
    pub(crate) fn with<R>(op: impl for<'id> FnOnce(Token<'id>) -> R) -> R {
        op(Token(marker::PhantomData))
    }

    pub(crate) fn with_ref<T: ?Sized, R>(
        value: &T,
        op: impl for<'id> FnOnce(Token<'id>, &'id T) -> R,
    ) -> R {
        op(Token(marker::PhantomData), value)
    }

    pub(crate) fn with_mut<T: ?Sized, R>(
        value: &mut T,
        op: impl for<'id> FnOnce(Token<'id>, &'id mut T) -> R,
    ) -> R {
        op(Token(marker::PhantomData), value)
    }

    pub(crate) const fn reborrow(&self) -> Token<'_> {
        Token(marker::PhantomData)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Branded<'id, T> {
    value: T,
    brand: Token<'id>,
}

impl<'id, T> Branded<'id, T> {
    pub(crate) const fn new(brand: Token<'id>, value: T) -> Self {
        Self { value, brand }
    }

    pub(crate) const fn value(&self) -> &T {
        &self.value
    }

    pub(crate) const fn brand(&self) -> Token<'id> {
        self.brand
    }

    pub(crate) fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub(crate) fn into_parts(self) -> (T, Token<'id>) {
        (self.value, self.brand)
    }
}

const _: () = {
    assert!(mem::size_of::<Token<'static>>() == 0);
    assert!(mem::align_of::<Token<'static>>() == 1);
    assert!(!mem::needs_drop::<Token<'static>>());
    assert!(mem::size_of::<Branded<'static, u64>>() == mem::size_of::<u64>());
    assert!(mem::align_of::<Branded<'static, u64>>() == mem::align_of::<u64>());
    assert!(!mem::needs_drop::<Branded<'static, u64>>());
    assert!(
        mem::size_of::<Option<Branded<'static, num::NonZero<usize>>>>()
            == mem::size_of::<Option<num::NonZero<usize>>>()
    );
};
