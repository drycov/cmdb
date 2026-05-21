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
    SYSTEM_NTP_CLIENT = "/system ntp client print"
    SYSTEM_NTP_CLIENT_DETAIL = "/system ntp client print detail"
    SYSTEM_NTP_CLIENT_SERVERS = "/system ntp client servers print"
    SYSTEM_NTP_CLIENT_SERVERS_DETAIL = "/system ntp client servers print detail"

    SYSTEM_CLOCK = "/system clock print"
    SYSTEM_ROUTERBOARD_UPGRADE = "/system routerboard upgrade"
    ROUTERBOARD_SETTINGS = "/system routerboard settings print"
    EXPORT_TERSE = "/export terse"
    EXPORT_COMPACT = "/export compact"

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
    BRIDGE_VLAN_DETAIL = "/interface bridge vlan print detail"
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
    IP_ADDRESS_DETAIL = "/ip address print detail"
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

    @classmethod
    def radius_remove_duplicates_keep_first(cls, service: str, address: str) -> str:
        service_quoted = cls._quote(service)
        address_quoted = cls._quote(address)
        return (
            f':local ids [/radius find where service={service_quoted} and address={address_quoted}]; '
            ':local keep ""; '
            ':foreach id in=$ids do={ '
            ':if ($keep = "") do={ :set keep $id } else={ /radius remove $id } '
            '}'
        )
    # ------------------------------
    # SCHEDULER
    # ------------------------------

    @classmethod
    def scheduler_find_by_name(cls, name: str) -> str:
        return f"/system scheduler print detail where name={cls._quote(name)}"

    @classmethod
    def scheduler_remove_by_name(cls, name: str) -> str:
        return f"/system scheduler remove [find where name={cls._quote(name)}]"

    @classmethod
    def scheduler_set(
        cls,
        *,
        name: str,
        start_time: str,
        start_date: str = "",
        interval: str,
        on_event: str,
        policy: str,
        disabled: str = "no",
    ) -> str:
        command = (
            f"/system scheduler set [find where name={cls._quote(name)}] "
            f"start-time={cls._quote(start_time)} "
            f"interval={cls._quote(interval)} "
            f"on-event={cls._quote(on_event)} "
            f"policy={cls._quote(policy)} "
            f"disabled={cls._quote(disabled)}"
        )
        if start_date:
            command += f" start-date={cls._quote(start_date)}"
        return command

    @classmethod
    def scheduler_add(
        cls,
        *,
        name: str,
        start_time: str,
        start_date: str = "",
        interval: str,
        on_event: str,
        policy: str,
        disabled: str = "no",
    ) -> str:
        command = (
            "/system scheduler add "
            f"name={cls._quote(name)} "
            f"start-time={cls._quote(start_time)} "
            f"interval={cls._quote(interval)} "
            f"on-event={cls._quote(on_event)} "
            f"policy={cls._quote(policy)} "
            f"disabled={cls._quote(disabled)}"
        )
        if start_date:
            command += f" start-date={cls._quote(start_date)}"
        return command

    @classmethod
    def ntp_client_set_enabled(cls, enabled: str) -> str:
        return f"/system ntp client set enabled={cls._quote(enabled)}"

    @classmethod
    def ntp_client_servers_reset(cls) -> str:
        return ":foreach i in=[/system ntp client servers find] do={ /system ntp client servers remove $i }"

    @classmethod
    def ntp_client_server_add(cls, address: str) -> str:
        return f"/system ntp client servers add address={cls._quote(address)}"

    @classmethod
    def watchdog_set(
        cls,
        *,
        automatic_supout: str,
        ping_start_after_boot: str,
        ping_timeout: str,
        watchdog_timer: str,
    ) -> str:
        return (
            "/system watchdog set "
            f"automatic-supout={cls._quote(automatic_supout)} "
            f"ping-start-after-boot={cls._quote(ping_start_after_boot)} "
            f"ping-timeout={cls._quote(ping_timeout)} "
            f"watchdog-timer={cls._quote(watchdog_timer)}"
        )
