pub mod common;

use std::{convert::Infallible, pin, rc::Rc};

use common::{
    retry::{BIND, ENDPOINT, Events, traces::Immediate},
    runtime::pooled::Capture,
};
use dope::{
    core::{
        driver::{
            life::{creation::Attempt, recovery},
            result::SubmitError,
            route::KeyTag,
            schedule::Progress,
            settings::Routes,
        },
        io::datagram::ReceiveError,
    },
    manifold::{
        app::dispatch::raw::{Manifold, Projection as _, Wakes},
        network::datagram::{Transport, hook::ingress},
    },
    runtime::executor::Executor,
};
use dope_quic::{
    client::Dialer,
    runtime::endpoint::{Endpoint, client::Plan},
};
use o3::depot::arena::slab::Vacancy;

#[test]
fn endpoint_wakes() {
    type Owner<'d> = Endpoint<'d, 1, Capture<'d, 1>>;
    type Activation<'d> = <Owner<'d> as Manifold<'d>>::Activate;

    assert!(
        <Activation<'_> as Wakes<'_, Owner<'_>, KeyTag<1>>>::ROUTES
            == Routes::singleton::<KeyTag<1>>()
    );
    assert!(<Activation<'_> as Wakes<'_, Owner<'_>, KeyTag<1>>>::select().is_some());
}

#[test]
fn dialer_wakes() {
    type Owner<'d> = Dialer<'d, 'd, 1, Events, Immediate>;
    type Activation<'d> = <Owner<'d> as Manifold<'d>>::Activate;

    assert!(
        <Activation<'_> as Wakes<'_, Owner<'_>, KeyTag<1>>>::ROUTES
            == Routes::singleton::<KeyTag<1>>()
    );
    assert!(<Activation<'_> as Wakes<'_, Owner<'_>, KeyTag<1>>>::select().is_some());
}

#[test]
fn stops_without_output() {
    let plan = Plan::<1>::new(BIND, ENDPOINT).expect("endpoint plan");
    let mut create = Attempt::new();
    let executor = Executor::new(
        &mut create,
        Events::settings(8, plan.as_ref()).expect("driver claims"),
    );
    executor
        .as_ref()
        .map_err(|error| error.kind())
        .expect("driver");
    let mut reports = Vec::new();
    executor.ok().expect("driver admission").run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let mut driver = session.driver();
                let endpoint: Endpoint<'_, 1, _> = plan
                    .bind(
                        Capture {
                            established: Rc::default(),
                            errors: Rc::default(),
                            received: Rc::default(),
                            stop: Rc::default(),
                        },
                        &mut driver,
                    )
                    .expect("bound endpoint");
                let mut endpoint = pin::pin!(endpoint);
                let clock = driver.driver_ref().clock();
                for (cause, runnable) in
                    [(Vacancy::Full, false), (Vacancy::IdentityExhausted, true)]
                {
                    <ingress::Coupled as ingress::Failure<'_, KeyTag<1>, _>>::failed(
                        endpoint.as_mut().inner_mut(),
                        ReceiveError::Submit(SubmitError::from(cause)),
                        clock.now(),
                        driver.state_token(),
                    );
                    let engine = endpoint.as_mut().inner_mut().handler_mut();
                    let progress =
                        Transport::progress(engine.as_ref(), clock, driver.state_token());
                    assert!(matches!(
                        (progress, runnable),
                        (Progress::Runnable, true) | (Progress::Quiescent, false)
                    ));
                }
            },
            recovery::Policy::new(
                |event| reports.push(event),
                |failure: recovery::Recovery<'_, '_>| -> Infallible {
                    panic!("native recovery: {:?}", failure.cause())
                },
            ),
        );
        result
            .as_ref()
            .map_err(|error| error.cause())
            .expect("driver retirement");
    });
    assert!(
        reports.is_empty(),
        "unexpected native retirement: {reports:?}"
    );
}
