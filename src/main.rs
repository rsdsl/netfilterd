use rsdsl_netfilterd::error::Result;

use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rsdsl_pd_config::PdConfig;
use rustables::expr::{
    Bitwise, HighLevelPayload, IPv6HeaderField, Nat, NatType, NetworkHeaderField, Register,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};
use signal_hook::{consts::SIGUSR1, iterator::Signals};

const GUA: Ipv6Addr = Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0);
const ULA: Ipv6Addr = Ipv6Addr::new(0xfd0b, 0x9272, 0x534e, 0, 0, 0, 0, 0);
const VPN_ULA: Ipv6Addr = Ipv6Addr::new(0xfd0b, 0x9272, 0x534e, 6, 0, 0, 0, 0);
const EXPOSED_VPN_ULA: Ipv6Addr = Ipv6Addr::new(0xfd0b, 0x9272, 0x534e, 7, 0, 0, 0, 0);

#[derive(Debug)]
struct Npt {
    postrouting: Chain,
    prerouting: Chain,
    map_vpn_to_gua: Rule,
    map_exposed_vpn_to_gua: Rule,
    map_gua_to_vpn: Rule,
    map_gua_to_exposed_vpn: Rule,
}

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

    let masq_outbound_modem = Rule::new(&postrouting)?
        .oface("eth1")?
        .dnetwork(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 0), 24)?.into())?
        .masquerade();
    batch.add(&masq_outbound_modem, MsgType::Add);

    let masq_outbound_wan = Rule::new(&postrouting)?.oface("ppp0")?.masquerade();
    batch.add(&masq_outbound_wan, MsgType::Add);

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
            .iface("ppp0")?
            .dport(port, Protocol::UDP)
            .dnat("10.128.40.252".parse()?, None);
        batch.add(&dnat_sip, MsgType::Add);
    }

    for port in 16384..=16482 {
        let dnat_rtp = Rule::new(&prerouting)?
            .iface("ppp0")?
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

    let allow_4in6 = Rule::new(&input)?.ip4in6().accept();
    batch.add(&allow_4in6, MsgType::Add);

    let allow_6in4 = Rule::new(&input)?.ip6in4().accept();
    batch.add(&allow_6in4, MsgType::Add);

    let allow_wan_dhcpv6 = Rule::new(&input)?
        .iface("ppp0")?
        .dport(546, Protocol::UDP)
        .accept();
    batch.add(&allow_wan_dhcpv6, MsgType::Add);

    let deny_isolated_vpn = Rule::new(&input)?
        .iface("eth0.30")?
        .dport(51820, Protocol::UDP)
        .drop();
    batch.add(&deny_isolated_vpn, MsgType::Add);

    let deny_isolated_exposed_vpn = Rule::new(&input)?
        .iface("eth0.30")?
        .dport(51821, Protocol::UDP)
        .drop();
    batch.add(&deny_isolated_exposed_vpn, MsgType::Add);

    let allow_any_vpn = Rule::new(&input)?.dport(51820, Protocol::UDP).accept();
    batch.add(&allow_any_vpn, MsgType::Add);

    let allow_any_exposed_vpn = Rule::new(&input)?.dport(51821, Protocol::UDP).accept();
    batch.add(&allow_any_exposed_vpn, MsgType::Add);

    let deny_wan_netdump = Rule::new(&input)?
        .iface("ppp0")?
        .dport(22, Protocol::TCP)
        .drop();
    batch.add(&deny_wan_netdump, MsgType::Add);

    let deny_wan_admin = Rule::new(&input)?
        .iface("ppp0")?
        .dport(8443, Protocol::TCP)
        .drop();
    batch.add(&deny_wan_admin, MsgType::Add);

    let deny_wan_dns = Rule::new(&input)?
        .iface("ppp0")?
        .dport(53, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dns, MsgType::Add);

    let deny_wan_dhcpv4 = Rule::new(&input)?
        .iface("ppp0")?
        .dport(67, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dhcpv4, MsgType::Add);

    let deny_wan_dhcpv6 = Rule::new(&input)?
        .iface("ppp0")?
        .dport(547, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dhcpv6, MsgType::Add);

    let deny_wan_dslite_netdump = Rule::new(&input)?
        .iface("dslite0")?
        .dport(22, Protocol::TCP)
        .drop();
    batch.add(&deny_wan_dslite_netdump, MsgType::Add);

    let deny_wan_dslite_admin = Rule::new(&input)?
        .iface("dslite0")?
        .dport(8443, Protocol::TCP)
        .drop();
    batch.add(&deny_wan_dslite_admin, MsgType::Add);

    let deny_wan_dslite_dns = Rule::new(&input)?
        .iface("dslite0")?
        .dport(53, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dslite_dns, MsgType::Add);

    let deny_wan_dslite_dhcpv4 = Rule::new(&input)?
        .iface("dslite0")?
        .dport(67, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dslite_dhcpv4, MsgType::Add);

    let deny_wan_dslite_dhcpv6 = Rule::new(&input)?
        .iface("dslite0")?
        .dport(547, Protocol::UDP)
        .drop();
    batch.add(&deny_wan_dslite_dhcpv6, MsgType::Add);

    let deny_wan6in4_netdump = Rule::new(&input)?
        .iface("he6in4")?
        .dport(22, Protocol::TCP)
        .drop();
    batch.add(&deny_wan6in4_netdump, MsgType::Add);

    let deny_wan6in4_admin = Rule::new(&input)?
        .iface("he6in4")?
        .dport(8443, Protocol::TCP)
        .drop();
    batch.add(&deny_wan6in4_admin, MsgType::Add);

    let deny_wan6in4_dns = Rule::new(&input)?
        .iface("he6in4")?
        .dport(53, Protocol::UDP)
        .drop();
    batch.add(&deny_wan6in4_dns, MsgType::Add);

    let deny_wan6in4_dhcpv4 = Rule::new(&input)?
        .iface("he6in4")?
        .dport(67, Protocol::UDP)
        .drop();
    batch.add(&deny_wan6in4_dhcpv4, MsgType::Add);

    let deny_wan6in4_dhcpv6 = Rule::new(&input)?
        .iface("he6in4")?
        .dport(547, Protocol::UDP)
        .drop();
    batch.add(&deny_wan6in4_dhcpv6, MsgType::Add);

    let deny_untrusted_netdump = Rule::new(&input)?
        .iface("eth0.20")?
        .dport(22, Protocol::TCP)
        .drop();
    batch.add(&deny_untrusted_netdump, MsgType::Add);

    let deny_untrusted_admin = Rule::new(&input)?
        .iface("eth0.20")?
        .dport(8443, Protocol::TCP)
        .drop();
    batch.add(&deny_untrusted_admin, MsgType::Add);

    let deny_exposed_netdump = Rule::new(&input)?
        .iface("eth0.40")?
        .dport(22, Protocol::TCP)
        .drop();
    batch.add(&deny_exposed_netdump, MsgType::Add);

    let deny_exposed_admin = Rule::new(&input)?
        .iface("eth0.40")?
        .dport(8443, Protocol::TCP)
        .drop();
    batch.add(&deny_exposed_admin, MsgType::Add);

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
        .iface("ppp0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_inbound, MsgType::Add);

    let clamp_mss_inbound_dslite = Rule::new(&forward)?
        .iface("dslite0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_inbound_dslite, MsgType::Add);

    let clamp_mss_inbound6in4 = Rule::new(&forward)?
        .iface("he6in4")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_inbound6in4, MsgType::Add);

    let clamp_mss_inbound_vpn = Rule::new(&forward)?
        .iface("wg0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_inbound_vpn, MsgType::Add);

    let clamp_mss_inbound_exposed_vpn = Rule::new(&forward)?
        .iface("wg1")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_inbound_exposed_vpn, MsgType::Add);

    let clamp_mss_outbound = Rule::new(&forward)?
        .oface("ppp0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_outbound, MsgType::Add);

    let clamp_mss_outbound_dslite = Rule::new(&forward)?
        .oface("dslite0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_outbound_dslite, MsgType::Add);

    let clamp_mss_outbound6in4 = Rule::new(&forward)?
        .oface("he6in4")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_outbound6in4, MsgType::Add);

    let clamp_mss_outbound_vpn = Rule::new(&forward)?
        .oface("wg0")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_outbound_vpn, MsgType::Add);

    let clamp_mss_outbound_exposed_vpn = Rule::new(&forward)?
        .oface("wg1")?
        .protocol(Protocol::TCP)
        .syn()?
        .clamp_mss_to_pmtu();
    batch.add(&clamp_mss_outbound_exposed_vpn, MsgType::Add);

    let allow_established = Rule::new(&forward)?.established()?.accept();
    batch.add(&allow_established, MsgType::Add);

    let allow_mgmt_to_modem = Rule::new(&forward)?.iface("eth0")?.oface("eth1")?.accept();
    batch.add(&allow_mgmt_to_modem, MsgType::Add);

    let allow_mgmt_to_wan = Rule::new(&forward)?.iface("eth0")?.oface("ppp0")?.accept();
    batch.add(&allow_mgmt_to_wan, MsgType::Add);

    let allow_mgmt_to_wan_dslite = Rule::new(&forward)?
        .iface("eth0")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_mgmt_to_wan_dslite, MsgType::Add);

    let allow_mgmt_to_wan6in4 = Rule::new(&forward)?
        .iface("eth0")?
        .oface("he6in4")?
        .accept();
    batch.add(&allow_mgmt_to_wan6in4, MsgType::Add);

    let allow_trusted_to_modem = Rule::new(&forward)?
        .iface("eth0.10")?
        .oface("eth1")?
        .accept();
    batch.add(&allow_trusted_to_modem, MsgType::Add);

    let allow_trusted_to_wan = Rule::new(&forward)?
        .iface("eth0.10")?
        .oface("ppp0")?
        .accept();
    batch.add(&allow_trusted_to_wan, MsgType::Add);

    let allow_trusted_to_wan_dslite = Rule::new(&forward)?
        .iface("eth0.10")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_trusted_to_wan_dslite, MsgType::Add);

    let allow_trusted_to_wan6in4 = Rule::new(&forward)?
        .iface("eth0.10")?
        .oface("he6in4")?
        .accept();
    batch.add(&allow_trusted_to_wan6in4, MsgType::Add);

    let allow_untrusted_to_wan = Rule::new(&forward)?
        .iface("eth0.20")?
        .oface("ppp0")?
        .accept();
    batch.add(&allow_untrusted_to_wan, MsgType::Add);

    let allow_untrusted_to_wan_dslite = Rule::new(&forward)?
        .iface("eth0.20")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_untrusted_to_wan_dslite, MsgType::Add);

    let allow_untrusted_to_wan6in4 = Rule::new(&forward)?
        .iface("eth0.20")?
        .oface("he6in4")?
        .accept();
    batch.add(&allow_untrusted_to_wan6in4, MsgType::Add);

    let allow_exposed_to_wan = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("ppp0")?
        .accept();
    batch.add(&allow_exposed_to_wan, MsgType::Add);

    let allow_exposed_to_wan_dslite = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_exposed_to_wan_dslite, MsgType::Add);

    let allow_exposed_to_wan6in4 = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("he6in4")?
        .accept();
    batch.add(&allow_exposed_to_wan6in4, MsgType::Add);

    let allow_exposed_to_trusted_sip = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("eth0.10")?
        .dport(5060, Protocol::UDP)
        .accept();
    batch.add(&allow_exposed_to_trusted_sip, MsgType::Add);

    let allow_exposed_to_vpn_sip = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("wg0")?
        .dport(5060, Protocol::UDP)
        .accept();
    batch.add(&allow_exposed_to_vpn_sip, MsgType::Add);

    let allow_exposed_to_exposed_vpn_sip = Rule::new(&forward)?
        .iface("eth0.40")?
        .oface("wg1")?
        .dport(5060, Protocol::UDP)
        .accept();
    batch.add(&allow_exposed_to_exposed_vpn_sip, MsgType::Add);

    let allow_vpn_to_modem = Rule::new(&forward)?.iface("wg0")?.oface("eth1")?.accept();
    batch.add(&allow_vpn_to_modem, MsgType::Add);

    let allow_vpn_to_wan = Rule::new(&forward)?.iface("wg0")?.oface("ppp0")?.accept();
    batch.add(&allow_vpn_to_wan, MsgType::Add);

    let allow_vpn_to_wan_dslite = Rule::new(&forward)?
        .iface("wg0")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_vpn_to_wan_dslite, MsgType::Add);

    let allow_vpn_to_wan6in4 = Rule::new(&forward)?.iface("wg0")?.oface("he6in4")?.accept();
    batch.add(&allow_vpn_to_wan6in4, MsgType::Add);

    let allow_exposed_vpn_to_modem = Rule::new(&forward)?.iface("wg1")?.oface("eth1")?.accept();
    batch.add(&allow_exposed_vpn_to_modem, MsgType::Add);

    let allow_exposed_vpn_to_wan = Rule::new(&forward)?.iface("wg1")?.oface("ppp0")?.accept();
    batch.add(&allow_exposed_vpn_to_wan, MsgType::Add);

    let allow_exposed_vpn_to_wan_dslite = Rule::new(&forward)?
        .iface("wg1")?
        .oface("dslite0")?
        .accept();
    batch.add(&allow_exposed_vpn_to_wan_dslite, MsgType::Add);

    let allow_exposed_vpn_to_wan6in4 = Rule::new(&forward)?.iface("wg1")?.oface("he6in4")?.accept();
    batch.add(&allow_exposed_vpn_to_wan6in4, MsgType::Add);

    let allow_any_to_exposed = Rule::new(&forward)?.oface("eth0.40")?.accept();
    batch.add(&allow_any_to_exposed, MsgType::Add);

    let allow_any_to_exposed_vpn = Rule::new(&forward)?.oface("wg1")?.accept();
    batch.add(&allow_any_to_exposed_vpn, MsgType::Add);

    let allow_icmp4_to_any = Rule::new(&forward)?.icmp().accept();
    batch.add(&allow_icmp4_to_any, MsgType::Add);

    let allow_icmp6_to_any = Rule::new(&forward)?.icmpv6().accept();
    batch.add(&allow_icmp6_to_any, MsgType::Add);

    batch.send()?;
    Ok(())
}

fn enable_npt(prefix: Ipv6Addr) -> Result<Npt> {
    let gua_net = IpNetwork::V6(Ipv6Network::new(GUA, 3).unwrap());
    let vpn_net = IpNetwork::V6(Ipv6Network::new(VPN_ULA, 64).unwrap());
    let exposed_vpn_net: IpNetwork = IpNetwork::V6(Ipv6Network::new(EXPOSED_VPN_ULA, 64).unwrap());

    let ifid_mask = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let everything_mask = vec![0xff; 16];

    let mut vpn_segments = prefix.segments();
    vpn_segments[3] += 6;
    let vpn_prefix = Ipv6Addr::from(vpn_segments);
    let vpn_subnet = IpNetwork::V6(Ipv6Network::new(vpn_prefix, 64).unwrap());

    let mut exposed_vpn_segments = prefix.segments();
    exposed_vpn_segments[3] += 7;
    let exposed_vpn_prefix = Ipv6Addr::from(exposed_vpn_segments);
    let exposed_vpn_subnet = IpNetwork::V6(Ipv6Network::new(exposed_vpn_prefix, 64).unwrap());

    let mut batch = Batch::new();

    let npt = Table::new(ProtocolFamily::Ipv6).with_name("npt");
    batch.add(&npt, MsgType::Add);

    // +-------------------+
    // | POSTROUTING chain |
    // +-------------------+

    let mut postrouting = Chain::new(&npt).with_name("POSTROUTING");

    postrouting.set_type(ChainType::Nat);
    postrouting.set_hook(Hook::new(HookClass::PostRouting, 100));
    postrouting.set_policy(ChainPolicy::Accept);

    batch.add(&postrouting, MsgType::Add);

    let map_vpn_to_gua = Rule::new(&postrouting)?
        .snetwork(vpn_net)?
        .dnetwork(gua_net)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask.clone(), vpn_prefix.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::SNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&map_vpn_to_gua, MsgType::Add);

    let map_exposed_vpn_to_gua = Rule::new(&postrouting)?
        .snetwork(exposed_vpn_net)?
        .dnetwork(gua_net)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(
            everything_mask.clone(),
            exposed_vpn_prefix.octets(),
        )?)
        .with_expr(Nat {
            nat_type: Some(NatType::SNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&map_exposed_vpn_to_gua, MsgType::Add);

    // +------------------+
    // | PREROUTING chain |
    // +------------------+

    let mut prerouting = Chain::new(&npt).with_name("PREROUTING");

    prerouting.set_type(ChainType::Nat);
    prerouting.set_hook(Hook::new(HookClass::PreRouting, -100));
    prerouting.set_policy(ChainPolicy::Accept);

    batch.add(&prerouting, MsgType::Add);

    let map_gua_to_vpn = Rule::new(&prerouting)?
        .dnetwork(vpn_subnet)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask.clone(), VPN_ULA.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::DNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&map_gua_to_vpn, MsgType::Add);

    let map_gua_to_exposed_vpn = Rule::new(&prerouting)?
        .dnetwork(exposed_vpn_subnet)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask, 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask, EXPOSED_VPN_ULA.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::DNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&map_gua_to_exposed_vpn, MsgType::Add);

    batch.send()?;
    Ok(Npt {
        postrouting,
        prerouting,
        map_vpn_to_gua,
        map_exposed_vpn_to_gua,
        map_gua_to_vpn,
        map_gua_to_exposed_vpn,
    })
}

fn update_npt(npt: &mut Npt, prefix: Ipv6Addr) -> Result<()> {
    let gua_net = IpNetwork::V6(Ipv6Network::new(GUA, 3).unwrap());
    let vpn_net = IpNetwork::V6(Ipv6Network::new(VPN_ULA, 64).unwrap());
    let exposed_vpn_net: IpNetwork = IpNetwork::V6(Ipv6Network::new(EXPOSED_VPN_ULA, 64).unwrap());

    let ifid_mask = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let everything_mask = vec![0xff; 16];

    let mut vpn_segments = prefix.segments();
    vpn_segments[3] += 6;
    let vpn_prefix = Ipv6Addr::from(vpn_segments);
    let vpn_subnet = IpNetwork::V6(Ipv6Network::new(vpn_prefix, 64).unwrap());

    let mut exposed_vpn_segments = prefix.segments();
    exposed_vpn_segments[3] += 7;
    let exposed_vpn_prefix = Ipv6Addr::from(exposed_vpn_segments);
    let exposed_vpn_subnet = IpNetwork::V6(Ipv6Network::new(exposed_vpn_prefix, 64).unwrap());

    let mut batch = Batch::new();

    batch.add(&npt.map_vpn_to_gua, MsgType::Del);
    batch.add(&npt.map_exposed_vpn_to_gua, MsgType::Del);
    batch.add(&npt.map_gua_to_vpn, MsgType::Del);
    batch.add(&npt.map_gua_to_exposed_vpn, MsgType::Del);

    // +-------------------+
    // | POSTROUTING chain |
    // +-------------------+

    npt.map_vpn_to_gua = Rule::new(&npt.postrouting)?
        .snetwork(vpn_net)?
        .dnetwork(gua_net)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask.clone(), vpn_prefix.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::SNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&npt.map_vpn_to_gua, MsgType::Add);

    npt.map_exposed_vpn_to_gua = Rule::new(&npt.postrouting)?
        .snetwork(exposed_vpn_net)?
        .dnetwork(gua_net)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(
            everything_mask.clone(),
            exposed_vpn_prefix.octets(),
        )?)
        .with_expr(Nat {
            nat_type: Some(NatType::SNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&npt.map_exposed_vpn_to_gua, MsgType::Add);

    // +------------------+
    // | PREROUTING chain |
    // +------------------+

    npt.map_gua_to_vpn = Rule::new(&npt.prerouting)?
        .dnetwork(vpn_subnet)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask.clone(), 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask.clone(), VPN_ULA.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::DNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&npt.map_gua_to_vpn, MsgType::Add);

    npt.map_gua_to_exposed_vpn = Rule::new(&npt.prerouting)?
        .dnetwork(exposed_vpn_subnet)?
        .with_expr(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
        )
        .with_expr(Bitwise::new(ifid_mask, 0u128.to_be_bytes())?)
        .with_expr(Bitwise::new(everything_mask, EXPOSED_VPN_ULA.octets())?)
        .with_expr(Nat {
            nat_type: Some(NatType::DNat),
            family: Some(ProtocolFamily::Ipv6),
            ip_register: Some(Register::Reg1),
            port_register: None,
        });
    batch.add(&npt.map_gua_to_exposed_vpn, MsgType::Add);

    batch.send()?;
    Ok(())
}

fn read_prefix() -> Result<Ipv6Addr> {
    let mut file = File::open(rsdsl_pd_config::LOCATION)?;
    let pdconfig: PdConfig = serde_json::from_reader(&mut file)?;

    Ok(pdconfig.prefix)
}

fn main() -> Result<()> {
    match nat() {
        Ok(_) => println!("enable nat"),
        Err(e) => {
            println!("can't enable nat: {}", e);
            return Err(e);
        }
    }

    match filter() {
        Ok(_) => println!("activate acl"),
        Err(e) => {
            println!("can't activate acl: {}", e);
            return Err(e);
        }
    }

    let prefix = read_prefix().unwrap_or(ULA);

    let mut npt = match enable_npt(prefix) {
        Ok(npt) => {
            println!("enable npt");
            npt
        }
        Err(e) => {
            println!("can't enable npt: {}", e);
            return Err(e);
        }
    };

    let mut signals = match Signals::new([SIGUSR1]) {
        Ok(signals) => signals,
        Err(e) => {
            println!("signal handling: {}", e);
            return Err(e.into());
        }
    };

    for _ in signals.forever() {
        let prefix = read_prefix().unwrap_or(ULA);

        match update_npt(&mut npt, prefix) {
            Ok(_) => println!("update npt"),
            Err(e) => println!("can't update npt: {}", e),
        }
    }

    println!("no more signals");
    Ok(())
}
