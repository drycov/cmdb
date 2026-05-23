"""Test cases for inventory normalization behavior."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from mikrotik_audit.app_runtime import TargetProvider
from mikrotik_audit.config import normalize_inventory_data


def test_normalize_inventory_groups_flattens_vlans():
    """Test that test normalize inventory groups flattens vlans."""
    payload = {
        "inventory_groups": [
            {
                "type": "core",
                "vlans": [
                    {
                        "id": 800,
                        "name": "vlan800_mgmt",
                        "networks": [{"subnet": "10.216.80.0/24", "gateway": "10.216.80.1"}],
                    }
                ],
            },
            {
                "type": "hex",
                "vlans": [
                    {
                        "id": 101,
                        "name": "vlan101_mgmt",
                        "networks": [{"subnet": "10.164.200.0/24", "gateway": "10.164.200.1"}],
                    }
                ],
            },
        ]
    }

    normalized = normalize_inventory_data(payload)

    assert "vlans" in normalized
    assert [item["id"] for item in normalized["vlans"]] == [800, 101]
    assert normalized["vlans"][0]["inventory_type"] == "core"
    assert normalized["vlans"][1]["inventory_type"] == "hex"


def test_target_provider_reads_grouped_inventory(tmp_path: Path):
    """Test that test target provider reads grouped inventory."""
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        "\n".join(
            [
                "inventory_groups:",
                "  - type: us",
                "    vlans:",
                "      - id: 850",
                "        name: vlan850_mgmt",
                "        networks:",
                "          - subnet: 10.216.92.0/30",
                "            gateway: 10.216.92.1",
            ]
        ),
        encoding="utf-8",
    )

    provider = TargetProvider(
        SimpleNamespace(
            inventory_file=str(inventory_path),
            exclude_gateways=True,
        )
    )

    assert provider.get_target_ips() == ["10.216.92.2"]


def test_normalize_environments_flattens_vlan_like_entries():
    """Test that test normalize environments flattens vlan like entries."""
    payload = {
        "environments": {
            "core": [
                {
                    "name": "core_r1_ukg",
                    "networks": [{"subnet": "10.216.100.1/32"}],
                }
            ],
            "hex": [
                {
                    "name": "hex_r1_ukg",
                    "id": 850,
                    "vlan_name": "vlan850_mgmt",
                    "ospf": {"instance": "mgmt_850"},
                    "networks": [{"subnet": "10.216.92.0/30", "gateway": "10.216.92.1"}],
                }
            ],
        }
    }

    normalized = normalize_inventory_data(payload)

    assert [item["id"] for item in normalized["vlans"]] == [850]
    assert normalized["vlans"][0]["name"] == "vlan850_mgmt"
    assert normalized["vlans"][0]["inventory_type"] == "hex"
    assert len(normalized["target_networks"]) == 2


def test_target_provider_reads_environment_inventory(tmp_path: Path):
    """Test that test target provider reads environment inventory."""
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        "\n".join(
            [
                "environments:",
                "  core:",
                "    - name: core_r1_ukg",
                "      networks:",
                "        - subnet: 10.216.100.1/32",
                "  us:",
                "    - name: us_r1_ukg",
                "      id: 800",
                "      vlan_name: vlan800_mgmt",
                "      ospf: null",
                "      networks:",
                "        - subnet: 10.216.80.0/30",
                "          gateway: 10.216.80.1",
            ]
        ),
        encoding="utf-8",
    )

    provider = TargetProvider(
        SimpleNamespace(
            inventory_file=str(inventory_path),
            exclude_gateways=True,
        )
    )

    assert provider.get_target_ips() == ["10.216.80.2", "10.216.100.1"]


def test_target_provider_preserves_environment_order(tmp_path: Path):
    """Test that test target provider preserves environment order."""
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        "\n".join(
            [
                "environments:",
                "  core:",
                "    - name: core_r1_ukg",
                "      networks:",
                "        - subnet: 10.216.100.1/32",
                "    - name: core_r3_ukg",
                "      networks:",
                "        - subnet: 10.216.100.3/32",
                "  us:",
                "    - name: us_r1_ukg",
                "      id: 800",
                "      vlan_name: vlan800_mgmt",
                "      ospf: null",
                "      networks:",
                "        - subnet: 10.216.80.0/30",
                "          gateway: 10.216.80.1",
                "  hex:",
                "    - name: hex_r1_ukg",
                "      id: 850",
                "      vlan_name: vlan850_mgmt",
                "      ospf:",
                "        instance: mgmt_850",
                "      networks:",
                "        - subnet: 10.216.92.0/30",
                "          gateway: 10.216.92.1",
            ]
        ),
        encoding="utf-8",
    )

    provider = TargetProvider(
        SimpleNamespace(
            inventory_file=str(inventory_path),
            exclude_gateways=True,
        )
    )

    assert provider.get_target_ips() == [
        "10.216.100.1",
        "10.216.100.3",
        "10.216.80.2",
        "10.216.92.2",
    ]
