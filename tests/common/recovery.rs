use dope::core::{driver::route, io::Reclaimed};

#[derive(Debug)]
pub struct Teardown<const N: usize> {
    routes: [(route::Route, bool); N],
    shutdown: bool,
}

#[derive(Debug)]
pub enum Error {
    Unexpected(Reclaimed),
    Duplicate(route::Route),
    DuplicateShutdown,
    Missing(route::Route),
}

impl<const N: usize> Teardown<N> {
    pub fn new(expected: [route::Id; N]) -> Self {
        Self {
            routes: expected.map(|id| (id.into(), false)),
            shutdown: false,
        }
    }

    pub fn verify(mut self, reports: Vec<Reclaimed>) -> Result<(), Error> {
        use dope::core::{Errno, io::event::batch::Flow};
        for event in reports {
            match event {
                Reclaimed::RecvRoute {
                    target,
                    result: Err(error),
                    flow: Flow::Last,
                } if error == Errno::CANCELED => {
                    let Some((route, seen)) = self
                        .routes
                        .iter_mut()
                        .find(|(route, _)| *route == target.route())
                    else {
                        return Err(Error::Unexpected(Reclaimed::RecvRoute {
                            target,
                            result: Err(error),
                            flow: Flow::Last,
                        }));
                    };
                    if *seen {
                        return Err(Error::Duplicate(*route));
                    }
                    *seen = true;
                }
                Reclaimed::Shutdown if !self.shutdown => self.shutdown = true,
                Reclaimed::Shutdown => return Err(Error::DuplicateShutdown),
                event => return Err(Error::Unexpected(event)),
            }
        }
        if let Some((route, _)) = self.routes.iter().find(|(_, seen)| !*seen) {
            return Err(Error::Missing(*route));
        }
        Ok(())
    }
}
