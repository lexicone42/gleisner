//! CLI subcommands.

#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod diff;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod inspect;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod learn;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod record;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod sbom;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod verify;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod wrap;
