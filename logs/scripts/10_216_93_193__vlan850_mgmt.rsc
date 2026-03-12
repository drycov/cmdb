# ============================================================
# Auto-generated RouterOS migration script
# Device IP: 10.216.93.193
# VLAN ID: 850
# Interface: vlan850_mgmt
# Matched subnet: 10.216.92.0/23
# Expected gateway: 10.216.92.1
# Target prefix: /23
# ============================================================

# Align prefix on target management interface only if current prefix differs
:foreach i in=[/ip address find where interface="vlan850_mgmt"] do={
    :local addr [/ip address get $i address]
    :local slashPos [:find $addr "/"]
    :if ($slashPos != nil) do={
        :local iponly [:pick $addr 0 $slashPos]
        :local currentPrefix [:pick $addr ($slashPos + 1) [:len $addr]]
        :if ($currentPrefix != "23") do={
            /ip address set $i address=($iponly . "/23")
        }
    }
}

# Ensure correct default route
:foreach r in=[/ip route find where dst-address="0.0.0.0/0"] do={
    :local gw [/ip route get $r gateway]
    :if ($gw != "10.216.92.1") do={
        /ip route remove $r
    }
}

:if ([:len [/ip route find where dst-address="0.0.0.0/0" and gateway="10.216.92.1"]] = 0) do={
    /ip route add disabled=no dst-address=0.0.0.0/0 gateway=10.216.92.1
}

# Remove legacy routing config
/routing bgp template remove [find name="default"]
/routing ospf area remove [find name="backbone-v2"]
/routing ospf instance remove [find name="default-v2"]
/routing bfd configuration remove [find where interfaces="all" and min-rx=200ms and min-tx=200ms and multiplier=5]

# Cleanup target config if already exists
/routing id remove [find name="rd1_850"]
/routing ospf area remove [find name="area-vlan850"]
/routing ospf instance remove [find name="mgmt_850"]
/routing filter rule remove [find chain="in-net"]
/routing filter rule remove [find chain="out-net"]
/routing ospf interface-template remove [find interfaces="vlan850_mgmt"]

# Create new routing/OSPF config
/routing id add disabled=no id=10.216.93.193 name=rd1_850 select-dynamic-id=only-vrf select-from-vrf=main
/routing ospf instance add disabled=no in-filter-chain=in-net name=mgmt_850 out-filter-chain=out-net router-id=rd1_850
/routing ospf area add area-id=0.0.85.0 disabled=no instance=mgmt_850 name=area-vlan850 type=stub

/routing filter rule add chain=in-net disabled=no rule="if (dst in 10.216.92.0/23) {accept}"
/routing filter rule add chain=in-net disabled=no rule="if (dst in 10.216.101.0/24) {accept}"
/routing filter rule add chain=in-net disabled=no rule="reject"
/routing filter rule add chain=out-net disabled=no rule="accept"

/routing ospf interface-template add area=area-vlan850 disabled=no interfaces=vlan850_mgmt
