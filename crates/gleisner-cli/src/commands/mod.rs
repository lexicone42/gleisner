//! CLI subcommands.

#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod record;
#[expect(
    unreachable_pub,
    reason = "binary crate — pub inside private module is fine"
)]
pub mod wrap;
