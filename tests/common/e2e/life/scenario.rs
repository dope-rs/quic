use std::num;

use crate::common::e2e::life::{self, contract, driver};
use contract::checks;

#[derive(Clone, Copy)]
pub struct Scenario<'a> {
    topology: life::Topology<'a>,
    steps: &'a [life::Step],
    polls: num::NonZero<u16>,
}

impl<'a> Scenario<'a> {
    pub const fn new(
        topology: life::Topology<'a>,
        steps: &'a [life::Step],
        polls: num::NonZero<u16>,
    ) -> Self {
        Self {
            topology,
            steps,
            polls,
        }
    }

    pub fn replay<D: driver::Driver>(
        self,
        driver: &mut D,
    ) -> life::Execution<contract::Error<D::Error>> {
        let topology = self.topology;
        let mut previous = match checks::validate_snapshots(topology, driver) {
            Ok(routes) => routes,
            Err(error) => return life::Execution::Failed(error),
        };
        for (expected, &step) in self.steps.iter().enumerate() {
            let expected = expected as u32;
            if step.ordinal() != expected {
                return life::Execution::Failed(contract::Error::WrongOrdinal {
                    expected,
                    observed: step.ordinal(),
                });
            }
            let valid = match step.try_validate(topology) {
                Ok(valid) => valid,
                Err(error) => {
                    return life::Execution::Failed(contract::Error::InvalidAction { step, error });
                }
            };
            let ticket = match driver.issue(valid) {
                driver::Issue::Issued(ticket) => ticket,
                driver::Issue::Failed(error) => {
                    return life::Execution::Failed(contract::Error::Driver(error));
                }
            };
            let mut left = self.polls.get();
            while left != 0 {
                match driver.poll(ticket) {
                    driver::Poll::Pending => left -= 1,
                    driver::Poll::Settled => break,
                    driver::Poll::Failed(error) => {
                        return life::Execution::Failed(contract::Error::Driver(error));
                    }
                }
            }
            if left == 0 {
                return life::Execution::Failed(contract::Error::SettlementTimeout {
                    step,
                    polls: self.polls.get(),
                });
            }
            if let Err(error) = checks::transition(topology, valid, driver, &mut previous) {
                return life::Execution::Failed(error);
            }
        }
        life::Execution::Complete
    }
}
