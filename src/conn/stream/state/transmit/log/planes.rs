use o3::depot::queue::indexed::keyed;

use crate::conn::machine::storage;
use crate::conn::stream::state::transmit::log;
use log::journal;

pub(super) enum All {}
pub(super) enum Delivery {}
pub(super) enum Probe {}
pub(super) enum Reclaim {}
pub(super) enum Retry {}

pub(super) trait Plane: Sized {
    type Value;
    type Tag;
    fn link(value: &Self::Value) -> &keyed::Link<storage::Key<Self::Tag>, Self>;
}

pub(super) trait Groups: Plane<Value = log::Group, Tag = log::GroupTag> {
    fn fifo(queues: &journal::Queues) -> &keyed::Fifo<storage::Key<log::GroupTag>, Self>;
    fn nodes(group: &log::Group) -> &keyed::Fifo<storage::Key<log::NodeTag>, Delivery>;
}

impl Plane for All {
    type Value = log::Node;
    type Tag = log::NodeTag;
    fn link(node: &log::Node) -> &keyed::Link<storage::Key<log::NodeTag>, Self> {
        &node.all
    }
}

impl Plane for Delivery {
    type Value = log::Node;
    type Tag = log::NodeTag;
    fn link(node: &log::Node) -> &keyed::Link<storage::Key<log::NodeTag>, Self> {
        &node.delivery
    }
}

impl Plane for Retry {
    type Value = log::Group;
    type Tag = log::GroupTag;
    fn link(group: &log::Group) -> &keyed::Link<storage::Key<log::GroupTag>, Self> {
        &group.retry
    }
}

impl Groups for Retry {
    fn fifo(queues: &journal::Queues) -> &keyed::Fifo<storage::Key<log::GroupTag>, Self> {
        &queues.retry
    }

    fn nodes(group: &log::Group) -> &keyed::Fifo<storage::Key<log::NodeTag>, Delivery> {
        &group.nodes.retry
    }
}

impl Plane for Probe {
    type Value = log::Group;
    type Tag = log::GroupTag;
    fn link(group: &log::Group) -> &keyed::Link<storage::Key<log::GroupTag>, Self> {
        &group.probe
    }
}

impl Groups for Probe {
    fn fifo(queues: &journal::Queues) -> &keyed::Fifo<storage::Key<log::GroupTag>, Self> {
        &queues.probe.chain
    }

    fn nodes(group: &log::Group) -> &keyed::Fifo<storage::Key<log::NodeTag>, Delivery> {
        &group.nodes.inflight
    }
}

impl Plane for Reclaim {
    type Value = log::Group;
    type Tag = log::GroupTag;
    fn link(group: &log::Group) -> &keyed::Link<storage::Key<log::GroupTag>, Self> {
        &group.reclaim
    }
}
