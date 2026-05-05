from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import npyscreen


ACTION_OPTIONS = [
    ("audit_full", "Run full audit"),
    ("audit_single", "Run single-device audit"),
    ("generate_script", "Generate remediation script"),
    ("phpipam_report", "Build phpIPAM report"),
    ("targets", "Show targets summary"),
    ("config", "Show config summary"),
    ("doctor", "Run environment checks"),
    ("quit", "Quit"),
]

ACTION_HELP = {
    "audit_full": (
        "Audit all devices from inventory and export the report."
    ),
    "audit_single": (
        "Audit one IP address. You can disable export for a quick check."
    ),
    "generate_script": (
        "Audit one IP address and generate a remediation script only for that device."
    ),
    "phpipam_report": (
        "Run audit plus phpIPAM comparison and export the inventory report."
    ),
    "targets": (
        "Show a short summary of resolved target IP addresses."
    ),
    "config": (
        "Show effective runtime configuration with secrets redacted."
    ),
    "doctor": (
        "Validate inventory, credentials, firmware directory, and integrations."
    ),
    "quit": "Exit interactive mode.",
}


@dataclass(slots=True)
class InteractiveSelection:
    action: str
    ip: str = ""
    export: bool = True


class ActionSelector(npyscreen.ActionForm):
    def create(self) -> None:
        self.selection: InteractiveSelection | None = None

        self.add(
            npyscreen.FixedText,
            value="MikroTik Audit Interactive Mode",
            editable=False,
            color="STANDOUT",
        )
        self.add(
            npyscreen.FixedText,
            value="Choose an action, optionally fill IP, then press OK.",
            editable=False,
        )

        self.action_widget = self.add(
            npyscreen.TitleSelectOne,
            name="Action",
            values=[label for _, label in ACTION_OPTIONS],
            max_height=len(ACTION_OPTIONS) + 1,
            scroll_exit=True,
        )
        self.action_widget.value = [0]

        self.ip_widget = self.add(
            npyscreen.TitleText,
            name="Target IP",
            value="",
        )
        self.export_widget = self.add(
            npyscreen.Checkbox,
            name="Export single-device audit result",
            value=True,
        )
        self.help_widget = self.add(
            npyscreen.Pager,
            name="Details",
            values=[ACTION_HELP["audit_full"]],
            max_height=6,
            editable=False,
        )

    def while_waiting(self) -> None:
        self._refresh_help()

    def on_ok(self) -> None:
        action = self._selected_action()
        ip = self.ip_widget.value.strip()

        if action in {"audit_single", "generate_script"} and not ip:
            npyscreen.notify_confirm(
                "Target IP is required for the selected action.",
                title="Input Required",
            )
            return

        self.selection = InteractiveSelection(
            action=action,
            ip=ip,
            export=bool(self.export_widget.value),
        )
        self.parentApp.setNextForm(None)

    def on_cancel(self) -> None:
        self.selection = InteractiveSelection(action="quit")
        self.parentApp.setNextForm(None)

    def _selected_action(self) -> str:
        indexes = self.action_widget.value or [0]
        return ACTION_OPTIONS[indexes[0]][0]

    def _refresh_help(self) -> None:
        action = self._selected_action()
        self.help_widget.values = [ACTION_HELP[action]]
        self.help_widget.display()


class InteractiveApp(npyscreen.NPSAppManaged):
    def onStart(self) -> None:
        self.addForm("MAIN", ActionSelector, name="MikroTik Audit")


def run_interactive_ui() -> dict[str, Any]:
    app = InteractiveApp()
    app.run()
    form = app.getForm("MAIN")

    if form.selection is None:
        return {"action": "quit"}

    return {
        "action": form.selection.action,
        "ip": form.selection.ip,
        "export": form.selection.export,
    }
