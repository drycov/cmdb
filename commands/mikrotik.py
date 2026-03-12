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

    # ------------------------------
    # INTERFACES
    # ------------------------------

    INTERFACE_PRINT = "/interface print"
    INTERFACE_COUNT = "/interface print count-only"

    # ------------------------------
    # FILES
    # ------------------------------

    FILE_PRINT = "/file print"
    FILE_LIST = "/file print detail"

    @staticmethod
    def file_print(filename: str) -> str:
        return f'/file print where name="{filename}"'

    # ------------------------------
    # USER AAA
    # ------------------------------

    USER_AAA_PRINT = "/user aaa print"
    USER_AAA_ENABLE_RADIUS = "/user aaa set use-radius=yes"

    # ------------------------------
    # RADIUS
    # ------------------------------

    @staticmethod
    def radius_count(service: str, address: str) -> str:
        return (
            f"/radius print count-only "
            f'where service="{service}" and address="{address}"'
        )

    @staticmethod
    def radius_add(service: str, address: str, secret: str) -> str:
        return (
            f"/radius add "
            f'service="{service}" '
            f'address="{address}" '
            f'secret="{secret}"'
        )

    @staticmethod
    def radius_remove(service: str, address: str) -> str:
        return (
            f"/radius remove "
            f'[find where service="{service}" and address="{address}"]'
        )

    # ------------------------------
    # ROUTERBOARD
    # ------------------------------

    ROUTERBOARD_SETTINGS = "/system routerboard settings print"

    # ------------------------------
    # STORAGE CHECK
    # ------------------------------

    SYSTEM_DISK = "/system resource print"

    # ------------------------------
    # OPTIONAL DIAGNOSTIC
    # ------------------------------

    SYSTEM_CLOCK = "/system clock print"
    SYSTEM_ROUTERBOARD_UPGRADE = "/system routerboard upgrade"

    INTERFACE_ETHERNET_DETAIL = "/interface ethernet print detail"
    INTERFACE_DETAIL = "/interface print detail"
    IP_NEIGHBOR_DETAIL = "/ip neighbor print detail"
    BRIDGE_PORT_DETAIL = "/interface bridge port print detail"
    INTERFACE_MAC_COMMENT_BRIEF = "/interface print detail without-paging brief"
