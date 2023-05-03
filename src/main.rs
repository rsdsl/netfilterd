use rsdsl_netfilterd::error::Result;

use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};

fn nat() -> Result<()> {
    let mut batch = Batch::new();

    let nat = Table::new(ProtocolFamily::Ipv4).with_name("nat");
    batch.add(&nat, MsgType::Add);

    // +-------------------+
    // | POSTROUTING chain |
    // +-------------------+

    let mut postrouting = Chain::new(&nat).with_name("POSTROUTING");

    postrouting.set_type(ChainType::Nat);
    postrouting.set_hook(Hook::new(HookClass::PostRouting, 100));
    postrouting.set_policy(ChainPolicy::Accept);

    batch.add(&postrouting, MsgType::Add);

    let rule = Rule::new(&postrouting)?.oface("rsppp0")?.masquerade();
    batch.add(&rule, MsgType::Add);

    // +------------------+
    // | PREROUTING chain |
    // +------------------+

    let mut prerouting = Chain::new(&nat).with_name("PREROUTING");

    prerouting.set_type(ChainType::Nat);
    prerouting.set_hook(Hook::new(HookClass::PreRouting, -100));
    prerouting.set_policy(ChainPolicy::Accept);

    batch.add(&prerouting, MsgType::Add);

    for port in 5060..=5080 {
        let dnat_sip = Rule::new(&prerouting)?
            .iface("rsppp0")?
            .dport(port, Protocol::UDP)
            .dnat("10.128.40.252".parse()?, None);
        batch.add(&dnat_sip, MsgType::Add);
    }

    for port in 16384..=16482 {
        let dnat_rtp = Rule::new(&prerouting)?
            .iface("rsppp0")?
            .dport(port, Protocol::UDP)
            .dnat("10.128.40.252".parse()?, None);
        batch.add(&dnat_rtp, MsgType::Add);
    }

    batch.send()?;
    Ok(())
}

fn filter() -> Result<()> {
    let mut batch = Batch::new();

    let filter = Table::new(ProtocolFamily::Inet).with_name("filter");
    batch.add(&filter, MsgType::Add);

    // +-------------+
    // | INPUT chain |
    // +-------------+

    let mut input = Chain::new(&filter).with_name("INPUT");

    input.set_type(ChainType::Filter);
    input.set_hook(Hook::new(HookClass::In, 0));
    input.set_policy(ChainPolicy::Accept);

    batch.add(&input, MsgType::Add);

    let allow_established = Rule::new(&input)?.established()?.accept();
    batch.add(&allow_established, MsgType::Add);

    let allow_icmp4 = Rule::new(&input)?.icmp().accept();
    batch.add(&allow_icmp4, MsgType::Add);

    let allow_icmp6 = Rule::new(&input)?.icmpv6().accept();
    batch.add(&allow_icmp6, MsgType::Add);

    let deny_wan4 = Rule::new(&input)?.iface("rsppp0")?.drop();
    batch.add(&deny_wan4, MsgType::Add);

    let allow_isolated_dhcp = Rule::new(&input)?
        .iface("eth0.30")?
        .dport(67, Protocol::UDP)
        .accept();
    batch.add(&allow_isolated_dhcp, MsgType::Add);

    let deny_isolated = Rule::new(&input)?.iface("eth0.30")?.drop();
    batch.add(&deny_isolated, MsgType::Add);

    let allow_untrusted_dhcp = Rule::new(&input)?
        .iface("eth0.20")?
        .dport(67, Protocol::UDP)
        .accept();
    batch.add(&allow_untrusted_dhcp, MsgType::Add);

    let allow_untrusted_dns = Rule::new(&input)?
        .iface("eth0.20")?
        .dport(53, Protocol::UDP)
        .accept();
    batch.add(&allow_untrusted_dns, MsgType::Add);

    let deny_untrusted = Rule::new(&input)?.iface("eth0.20")?.drop();
    batch.add(&deny_untrusted, MsgType::Add);

    // +---------------+
    // | FORWARD chain |
    // +---------------+

    let mut forward = Chain::new(&filter).with_name("FORWARD");

    forward.set_type(ChainType::Filter);
    forward.set_hook(Hook::new(HookClass::Forward, 0));
    forward.set_policy(ChainPolicy::Drop);

    batch.add(&forward, MsgType::Add);

    let deny_isolated_to_any = Rule::new(&forward)?.iface("eth0.30")?.drop();
    batch.add(&deny_isolated_to_any, MsgType::Add);

    let deny_any_to_isolated = Rule::new(&forward)?.oface("eth0.30")?.drop();
    batch.add(&deny_any_to_isolated, MsgType::Add);

    let clamp_mss_inbound = Rule::new(&forward)?
        .iface("rsppp0")?
        .protocol(Protocol::TCP)
        .syn()?
        .set_mss(1452);
    batch.add(&clamp_mss_inbound, MsgType::Add);

    let clamp_mss_outbound = Rule::new(&forward)?
        .oface("rsppp0")?
        .protocol(Protocol::TCP)
        .syn()?
        .set_mss(1452);
    batch.add(&clamp_mss_outbound, MsgType::Add);

    let allow_established = Rule::new(&forward)?.established()?.accept();
    batch.add(&allow_established, MsgType::Add);

    let allow_mgmt_to_wan4 = Rule::new(&forward)?
        .iface("eth0")?
        .oface("rsppp0")?
        .accept();
    batch.add(&allow_mgmt_to_wan4, MsgType::Add);

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

    let allow_icmp4_to_any = Rule::new(&forward)?.icmp().accept();
    batch.add(&allow_icmp4_to_any, MsgType::Add);

    let allow_icmp6_to_any = Rule::new(&forward)?.icmpv6().accept();
    batch.add(&allow_icmp6_to_any, MsgType::Add);

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
