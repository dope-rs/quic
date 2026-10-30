use crate::conn::stream::resident::slot::store::scope;
use crate::conn::stream::state::receive::recv::{self, map};
use crate::conn::stream::state::resident::scopes;
use crate::stream::Recv;

pub(in crate::conn::stream::state::receive::recv::map::scope) enum Bound<
    'id,
    'table,
    'body,
    B: Recv,
> {
    Existing {
        lease: scope::Lease<'id, map::Side>,
        resident: scopes::Lease<'table>,
        data: recv::Prepared<'body, B>,
    },
    Fresh {
        lease: scope::Fresh<'id, map::Side>,
        resident: scopes::Fresh<'table>,
        data: recv::Prepared<'body, B>,
    },
}
