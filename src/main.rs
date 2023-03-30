use rsdsl_netfilterd::error::Result;

use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
};

fn nat() -> Result<()> {
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

    batch.send()?;
    Ok(())
}

fn filter() -> Result<()> {
    let mut batch = Batch::new();

    let filter = Table::new(ProtocolFamily::Inet).with_name("filter");
    batch.add(&filter, MsgType::Add);

    let mut forward = Chain::new(&filter).with_name("FORWARD");

    forward.set_type(ChainType::Filter);
    forward.set_hook(Hook::new(HookClass::Forward, 0));
    forward.set_policy(ChainPolicy::Drop);

    batch.add(&forward, MsgType::Add);

    let allow_established = Rule::new(&forward)?.established()?.accept();
    batch.add(&allow_established, MsgType::Add);

    let allow_trusted_to_wan4 = Rule::new(&forward)?
        .iface("eth0.10")?
        .oface("rsppp0")?
        .accept();
    batch.add(&allow_trusted_to_wan4, MsgType::Add);

    let allow_untrusted_to_wan4 = Rule::new(&forward)?
        .iface("eth0.20")?
        .oface("rsppp0")?
        .accept();
    batch.add(&allow_untrusted_to_wan4, MsgType::Add);

    let allow_exposed_to_wan4 = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("rsppp0")?
        .accept();
    batch.add(&allow_exposed_to_wan4, MsgType::Add);

    let allow_any_to_exposed = Rule::new(&forward)?.oface("eth0.40")?.accept();
    batch.add(&allow_any_to_exposed, MsgType::Add);

    let allow_icmp4 = Rule::new(&forward)?.icmp().accept();
    batch.add(&allow_icmp4, MsgType::Add);

    let allow_icmp6 = Rule::new(&forward)?.icmpv6().accept();
    batch.add(&allow_icmp6, MsgType::Add);

    batch.send()?;
    Ok(())
}

fn main() -> Result<()> {
    match nat() {
        Ok(_) => println!("[netfilterd] enable nat"),
        Err(e) => {
            println!("[netfilterd] can't enable nat: {}", e);
            return Err(e);
        }
    }

    match filter() {
        Ok(_) => println!("[netfilterd] activate acl"),
        Err(e) => {
            println!("[netfilterd] can't activate acl: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
