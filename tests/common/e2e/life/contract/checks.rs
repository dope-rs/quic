use crate::common::e2e::life::{self, contract, driver, identity, state};

/// Action checks preserve equal or increasing counters; cycling alone needs
/// a separate check that the CID epoch does not decrease.
pub(in crate::common::e2e::life) fn transition<D: driver::Driver>(
    topology: life::Topology<'_>,
    valid: life::ValidStep,
    driver: &D,
    previous: &mut [state::Route; life::MAX_ROUTES],
) -> Result<(), contract::Error<D::Error>> {
    let step = valid.step();
    let (target, change) = valid.action().parts();
    for spec in topology.routes().iter().copied() {
        let route = spec.route();
        let before = previous[usize::from(route.get())];
        let current = driver.snapshot(route).map_err(contract::Error::Driver)?;
        let owned = match target {
            life::Target::All => true,
            life::Target::Transport(id) => spec.transport() == id,
            life::Target::Route(id) => route == id,
        };

        if !owned {
            require_unchanged(step, route, before, current)?;
            require_same(
                step,
                route,
                contract::Field::Accepted,
                before.delivery().accepted(),
                current.delivery().accepted(),
            )?;
        } else {
            match change {
                life::Change::Probe(sequence) => {
                    require_probe(
                        step,
                        route,
                        sequence,
                        before.delivery().accepted(),
                        current.delivery().accepted(),
                    )?;
                    require_unchanged(step, route, before, current)?;
                }
                life::Change::Rotate => {
                    require_progress(step, route, before.cid(), current.cid())?;
                    require_same(
                        step,
                        route,
                        contract::Field::TransportEpoch,
                        before.binding().epoch(),
                        current.binding().epoch(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ClientGeneration,
                        before.connection().client(),
                        current.connection().client(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ServerGeneration,
                        before.connection().server(),
                        current.connection().server(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::PathEpoch,
                        before.binding().path(),
                        current.binding().path(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ConnectionWitness,
                        before.connection().witness(),
                        current.connection().witness(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::Accepted,
                        before.delivery().accepted(),
                        current.delivery().accepted(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::Live,
                        before.delivery().is_live(),
                        current.delivery().is_live(),
                    )?;
                }
                life::Change::Rebind { epoch, sequence } => {
                    if current.binding().epoch() != epoch || epoch <= before.binding().epoch() {
                        return Err(contract::Error::ActionNotApplied { step, route });
                    }
                    require_progress(
                        step,
                        route,
                        before.binding().path(),
                        current.binding().path(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ClientGeneration,
                        before.connection().client(),
                        current.connection().client(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ServerGeneration,
                        before.connection().server(),
                        current.connection().server(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::CidEpoch,
                        before.cid(),
                        current.cid(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ConnectionWitness,
                        before.connection().witness(),
                        current.connection().witness(),
                    )?;
                    require_probe(
                        step,
                        route,
                        sequence,
                        before.delivery().accepted(),
                        current.delivery().accepted(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::Live,
                        before.delivery().is_live(),
                        current.delivery().is_live(),
                    )?;
                }
                life::Change::Cycle => {
                    require_progress(
                        step,
                        route,
                        before.connection().client(),
                        current.connection().client(),
                    )?;
                    require_progress(
                        step,
                        route,
                        before.connection().server(),
                        current.connection().server(),
                    )?;
                    if current.connection().witness() == before.connection().witness() {
                        return Err(contract::Error::ActionNotApplied { step, route });
                    }
                    require_same(
                        step,
                        route,
                        contract::Field::TransportEpoch,
                        before.binding().epoch(),
                        current.binding().epoch(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::PathEpoch,
                        before.binding().path(),
                        current.binding().path(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::Accepted,
                        before.delivery().accepted(),
                        current.delivery().accepted(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::Live,
                        before.delivery().is_live(),
                        current.delivery().is_live(),
                    )?;
                }
                life::Change::Drain => {
                    if current.delivery().delivered() != current.delivery().accepted()
                        || current.delivery().is_live()
                    {
                        return Err(contract::Error::NotDrained {
                            route,
                            accepted: current.delivery().accepted(),
                            delivered: current.delivery().delivered(),
                            live: current.delivery().is_live(),
                        });
                    }
                    require_same(
                        step,
                        route,
                        contract::Field::Accepted,
                        before.delivery().accepted(),
                        current.delivery().accepted(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::TransportEpoch,
                        before.binding().epoch(),
                        current.binding().epoch(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ClientGeneration,
                        before.connection().client(),
                        current.connection().client(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ServerGeneration,
                        before.connection().server(),
                        current.connection().server(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::CidEpoch,
                        before.cid(),
                        current.cid(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::PathEpoch,
                        before.binding().path(),
                        current.binding().path(),
                    )?;
                    require_same(
                        step,
                        route,
                        contract::Field::ConnectionWitness,
                        before.connection().witness(),
                        current.connection().witness(),
                    )?;
                }
            }
        }
        validate_snapshot(spec, current)?;
        if owned && change == life::Change::Cycle {
            monotonic(
                route,
                contract::Field::CidEpoch,
                before.cid(),
                current.cid(),
            )?;
        }
        monotonic(
            route,
            contract::Field::Delivered,
            before.delivery().delivered(),
            current.delivery().delivered(),
        )?;
        previous[usize::from(route.get())] = current;
    }
    Ok(())
}

fn require_unchanged<E>(
    step: life::Step,
    route: identity::RouteId,
    before: state::Route,
    current: state::Route,
) -> Result<(), contract::Error<E>> {
    require_same(
        step,
        route,
        contract::Field::TransportEpoch,
        before.binding().epoch(),
        current.binding().epoch(),
    )?;
    require_same(
        step,
        route,
        contract::Field::ClientGeneration,
        before.connection().client(),
        current.connection().client(),
    )?;
    require_same(
        step,
        route,
        contract::Field::ServerGeneration,
        before.connection().server(),
        current.connection().server(),
    )?;
    require_same(
        step,
        route,
        contract::Field::CidEpoch,
        before.cid(),
        current.cid(),
    )?;
    require_same(
        step,
        route,
        contract::Field::PathEpoch,
        before.binding().path(),
        current.binding().path(),
    )?;
    require_same(
        step,
        route,
        contract::Field::ConnectionWitness,
        before.connection().witness(),
        current.connection().witness(),
    )?;
    require_same(
        step,
        route,
        contract::Field::Live,
        before.delivery().is_live(),
        current.delivery().is_live(),
    )
}

fn require_same<E, T: Eq>(
    step: life::Step,
    route: identity::RouteId,
    field: contract::Field,
    before: T,
    current: T,
) -> Result<(), contract::Error<E>> {
    if current != before {
        return Err(contract::Error::UnexpectedMutation { step, route, field });
    }
    Ok(())
}

fn require_probe<E>(
    step: life::Step,
    route: identity::RouteId,
    sequence: u32,
    before: u64,
    after: u64,
) -> Result<(), contract::Error<E>> {
    let sequence = u64::from(sequence);
    if before != sequence || after != sequence + 1 {
        return Err(contract::Error::ProbeCount {
            step,
            route,
            before,
            after,
        });
    }
    Ok(())
}

fn require_progress<E, T: Ord>(
    step: life::Step,
    route: identity::RouteId,
    before: T,
    current: T,
) -> Result<(), contract::Error<E>> {
    if current <= before {
        return Err(contract::Error::ActionNotApplied { step, route });
    }
    Ok(())
}

pub(in crate::common::e2e::life) fn validate_snapshots<D: driver::Driver>(
    topology: life::Topology<'_>,
    driver: &D,
) -> Result<[state::Route; life::MAX_ROUTES], contract::Error<D::Error>> {
    let mut routes = [state::Route::EMPTY; life::MAX_ROUTES];
    for spec in topology.routes().iter().copied() {
        let route = spec.route();
        let current = driver.snapshot(route).map_err(contract::Error::Driver)?;
        validate_snapshot(spec, current)?;
        routes[usize::from(route.get())] = current;
    }
    Ok(routes)
}

fn validate_snapshot<E>(
    spec: life::RouteSpec,
    current: state::Route,
) -> Result<(), contract::Error<E>> {
    let route = spec.route();
    if current.spec().route() != route {
        return Err(contract::Error::WrongRoute {
            expected: route,
            observed: current.spec().route(),
        });
    }
    if current.spec().transport() != spec.transport() {
        return Err(contract::Error::WrongTransport {
            route,
            expected: spec.transport(),
            observed: current.spec().transport(),
        });
    }
    if current.spec().shard() != spec.shard() {
        return Err(contract::Error::WrongShard {
            route,
            expected: spec.shard(),
            observed: current.spec().shard(),
        });
    }
    if current.delivery().delivered() > current.delivery().accepted() {
        return Err(contract::Error::UnsentDelivery {
            route,
            accepted: current.delivery().accepted(),
            delivered: current.delivery().delivered(),
        });
    }
    Ok(())
}

fn monotonic<E, T: Ord>(
    route: identity::RouteId,
    field: contract::Field,
    before: T,
    current: T,
) -> Result<(), contract::Error<E>> {
    if current < before {
        return Err(contract::Error::CounterRegressed { route, field });
    }
    Ok(())
}
