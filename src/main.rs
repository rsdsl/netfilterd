use rsdsl_netfilterd::error::Result;

use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
};

fn main() -> Result<()> {
    let mut batch = Batch::new();

    let nat = Table::new(ProtocolFamily::Ipv4).with_name("nat");
    batch.add(&nat, MsgType::Add);

    let mut postrouting = Chain::new(&nat).with_name("POSTROUTING");

    postrouting.set_type(ChainType::Nat);
    postrouting.set_hook(Hook::new(HookClass::PostRouting, 100));
    postrouting.set_policy(ChainPolicy::Accept);

    batch.add(&postrouting, MsgType::Add);

    let rule = Rule::new(&postrouting)?.oface("rsppp0")?.masquerade();
    batch.add(&rule, MsgType::Add);

    Ok(batch.send()?)
}
