from __future__ import annotations


class MikroTikCommands:
    # ------------------------------
    # SYSTEM
    # ------------------------------

    SYSTEM_RESOURCE = "/system resource print"
    SYSTEM_IDENTITY = "/system identity print"
    SYSTEM_ROUTERBOARD = "/system routerboard print"
    SYSTEM_LICENSE = "/system license print"
    SYSTEM_PACKAGE = "/system package print"
    SYSTEM_PACKAGE_UPDATE = "/system package update print"
    SYSTEM_REBOOT = "/system reboot"
    SYSTEM_SCHEDULER_DETAIL = "/system scheduler print detail"

    SYSTEM_CLOCK = "/system clock print"
    SYSTEM_ROUTERBOARD_UPGRADE = "/system routerboard upgrade"
    ROUTERBOARD_SETTINGS = "/system routerboard settings print"

    WATCHDOG_PRINT = "/system watchdog print"
    WATCHDOG_ENABLE = "/system watchdog set enabled=yes"
    WATCHDOG_REMOVE_IP = "/system watchdog remove [find where type=ip]"

    # ------------------------------
    # INTERFACES
    # ------------------------------

    INTERFACE_PRINT = "/interface print"
    INTERFACE_COUNT = "/interface print count-only"
    INTERFACE_DETAIL = "/interface print detail"
    INTERFACE_ETHERNET_DETAIL = "/interface ethernet print detail"
    INTERFACE_MAC_COMMENT_BRIEF = "/interface print detail without-paging brief"

    BRIDGE_PORT_DETAIL = "/interface bridge port print detail"
    BRIDGE_DETAIL = "/interface bridge print detail"
    VLAN_DETAIL = "/interface vlan print detail"
    IP_NEIGHBOR_DETAIL = "/ip neighbor print detail"
    ROUTING_OSPF_INSTANCE_DETAIL = "/routing ospf instance print detail"
    ROUTING_OSPF_NEIGHBOR_DETAIL = "/routing ospf neighbor print detail"

    # ------------------------------
    # FILES
    # ------------------------------

    FILE_PRINT = "/file print"
    FILE_LIST = "/file print detail"

    # ------------------------------
    # USER AAA
    # ------------------------------

    USER_AAA_PRINT = "/user aaa print"
    USER_AAA_ENABLE_RADIUS = "/user aaa set use-radius=yes"
    RADIUS_DETAIL = "/radius print detail"
    DHCP_SERVER_DETAIL = "/ip dhcp-server print detail"
    DHCP_CLIENT_DETAIL = "/ip dhcp-client print detail"
    IP_SERVICE_DETAIL = "/ip service print detail"
    FIREWALL_FILTER_DETAIL = "/ip firewall filter print detail"
    FIREWALL_NAT_DETAIL = "/ip firewall nat print detail"
    IP_ROUTE_DETAIL = "/ip route print detail"

    @staticmethod
    def _quote(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    @classmethod
    def file_print(cls, filename: str) -> str:
        return f"/file print where name={cls._quote(filename)}"

    @classmethod
    def radius_count(cls, service: str, address: str) -> str:
        return (
            "/radius print count-only "
            f"where service={cls._quote(service)} and address={cls._quote(address)}"
        )

    @classmethod
    def radius_add(cls, service: str, address: str, secret: str) -> str:
        return (
            "/radius add "
            f"service={cls._quote(service)} "
            f"address={cls._quote(address)} "
            f"secret={cls._quote(secret)}"
        )

    @classmethod
    def radius_remove(cls, service: str, address: str) -> str:
        return (
            "/radius remove "
            f"[find where service={cls._quote(service)} and address={cls._quote(address)}]"
        )
