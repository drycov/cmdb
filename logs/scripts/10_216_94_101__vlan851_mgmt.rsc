# ============================================================
# Auto-generated RouterOS migration script
# Device IP: 10.216.94.101
# VLAN ID: 851
# Interface: vlan851_mgmt
# Matched subnet: 10.216.94.0/23
# Expected gateway: 10.216.94.1
# Target prefix: /23
# ============================================================

# Align prefix on target management interface only if current prefix differs
:foreach i in=[/ip address find where interface="vlan851_mgmt"] do={
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
    :if ($gw != "10.216.94.1") do={
        /ip route remove $r
    }
}

:if ([:len [/ip route find where dst-address="0.0.0.0/0" and gateway="10.216.94.1"]] = 0) do={
    /ip route add disabled=no dst-address=0.0.0.0/0 gateway=10.216.94.1
}

# Remove legacy routing config
/routing bgp template remove [find name="default"]
/routing ospf area remove [find name="backbone-v2"]
/routing ospf instance remove [find name="default-v2"]
/routing bfd configuration remove [find where interfaces="all" and min-rx=200ms and min-tx=200ms and multiplier=5]

# Cleanup target config if already exists
/routing id remove [find name="rd3_851"]
/routing ospf area remove [find name="area-vlan851"]
/routing ospf instance remove [find name="mgmt_851"]
/routing filter rule remove [find chain="in-net"]
/routing filter rule remove [find chain="out-net"]
/routing ospf interface-template remove [find interfaces="vlan851_mgmt"]

# Create new routing/OSPF config
/routing id add disabled=no id=10.216.94.101 name=rd3_851 select-dynamic-id=only-vrf select-from-vrf=main
/routing ospf instance add disabled=no in-filter-chain=in-net name=mgmt_851 out-filter-chain=out-net router-id=rd3_851
/routing ospf area add area-id=0.0.85.1 disabled=no instance=mgmt_851 name=area-vlan851 type=stub

/routing filter rule add chain=in-net disabled=no rule="if (dst in 10.216.94.0/23) {accept}"
/routing filter rule add chain=in-net disabled=no rule="reject"
/routing filter rule add chain=out-net disabled=no rule="accept"

/routing ospf interface-template add area=area-vlan851 disabled=no interfaces=vlan851_mgmt
