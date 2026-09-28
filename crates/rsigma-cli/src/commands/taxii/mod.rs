//! TAXII collection sync into a local STIX store (`taxii-sync` feature).

mod sync;

use clap::Subcommand;

use crate::output::OutputCtx;

pub(crate) use sync::{TaxiiSyncArgs, cmd_taxii_sync};

#[derive(Subcommand)]
pub(crate) enum TaxiiCommands {
    /// Fetch a TAXII collection and persist objects in a local store
    Sync(TaxiiSyncArgs),
}

pub(crate) fn dispatch_taxii(cmd: TaxiiCommands, ctx: OutputCtx) {
    match cmd {
        TaxiiCommands::Sync(args) => cmd_taxii_sync(args, ctx),
    }
}
