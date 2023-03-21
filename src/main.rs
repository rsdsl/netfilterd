use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;

    ipt.append("nat", "POSTROUTING", "-o rsppp0 -j MASQUERADE")?;

    Ok(())
}
