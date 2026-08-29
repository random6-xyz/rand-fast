use anyhow::Result;
use crate::cli::OffCpuArgs;
pub fn run(_args: OffCpuArgs) -> Result<()> {
    println!("Off-CPU diagnostics: futex and lock wait tracking (stub, see v0.5)");
    Ok(())
}
