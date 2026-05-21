from __future__ import annotations

import ipaddress
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, ListView, RichLog, Static, TextArea


ACTION_LABELS: list[tuple[str, str]] = [
    ("Full audit", "audit_full"),
    ("Single-device audit", "audit_single"),
    ("Generate remediation script", "generate_script"),
    ("Targeted remediation", "remediate"),
    ("Application settings", "app_settings"),
    ("Inventory settings", "inventory_settings"),
    ("phpIPAM report", "phpipam_report"),
    ("Targets browser", "targets"),
    ("Doctor", "doctor"),
    ("Quit", "quit"),
]

REMEDIATION_DOMAINS = ["ntp", "watchdog", "scheduler"]


@dataclass(slots=True)
class InteractiveSelection:
    action: str = "quit"
    ip: str = ""
    export: bool = True
    apply: bool = False
    remediation_domains: list[str] = field(default_factory=list)
    setup_values: dict[str, Any] = field(default_factory=dict)
    confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ip": self.ip.strip(),
            "export": self.export,
            "apply": self.apply,
            "remediation_domains": list(self.remediation_domains),
            "setup_values": dict(self.setup_values),
            "confirmed": self.confirmed,
        }


@dataclass(slots=True)
class OutputPayload:
    title: str
    text: str = ""
    summary_lines: list[str] = field(default_factory=list)
    list_title: str = ""
    list_items: list[str] = field(default_factory=list)


InlineHandler = Callable[[InteractiveSelection], OutputPayload]
TargetItemHandler = Callable[[str, str], OutputPayload]
InventoryEditorSaver = Callable[[str], str]
AppEditorSaver = Callable[[str, str], str]


class ActionListItem(ListItem):
    def __init__(self, label: str, action: str) -> None:
        super().__init__(Label(label))
        self.label_text = label
        self.action = action


class TargetListItem(ListItem):
    def __init__(self, ip: str) -> None:
        super().__init__(Label(ip))
        self.ip = ip


class InventoryEditorScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "cancel", "Close"),
    ]

    def __init__(self, *, initial_text: str, saver: InventoryEditorSaver) -> None:
        super().__init__()
        self.initial_text = initial_text
        self.saver = saver

    def compose(self) -> ComposeResult:
        with Vertical(id="inventory-editor"):
            yield Static("Inventory Settings Editor", classes="pane-title")
            yield Static("Edit the inventory YAML and press Ctrl+S to save.", id="inventory-editor-help")
            yield TextArea(self.initial_text, id="inventory-editor-text")
            with Horizontal(id="inventory-editor-buttons"):
                yield Button("Save", id="inventory-editor-save", variant="success")
                yield Button("Close", id="inventory-editor-close")

    def on_mount(self) -> None:
        self.query_one("#inventory-editor-text", TextArea).focus()

    def action_save(self) -> None:
        editor = self.query_one("#inventory-editor-text", TextArea)
        try:
            message = self.saver(editor.text)
        except Exception as exc:
            self.notify(str(exc), title="Save failed", severity="error")
            return
        self.notify("Inventory settings saved.", title="Saved", severity="information")
        self.dismiss()
        self.app.call_after_refresh(self.app._write_output_lines, "Inventory Settings", message.splitlines())

    def action_cancel(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#inventory-editor-save")
    def _save_pressed(self) -> None:
        self.action_save()

    @on(Button.Pressed, "#inventory-editor-close")
    def _close_pressed(self) -> None:
        self.action_cancel()


class AppSettingsEditorScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "cancel", "Close"),
    ]

    def __init__(
        self,
        *,
        secrets_text: str,
        env_text: str,
        saver: AppEditorSaver,
    ) -> None:
        super().__init__()
        self.secrets_text = secrets_text
        self.env_text = env_text
        self.saver = saver

    def compose(self) -> ComposeResult:
        with Vertical(id="app-editor"):
            yield Static("Application Settings Editor", classes="pane-title")
            yield Static(
                "Edit secrets.yml and .env, then press Ctrl+S to save both together.",
                id="app-editor-help",
            )
            yield Static("secrets.yml", classes="pane-title")
            yield TextArea(self.secrets_text, id="app-editor-secrets")
            yield Static(".env", classes="pane-title")
            yield TextArea(self.env_text, id="app-editor-env")
            with Horizontal(id="app-editor-buttons"):
                yield Button("Save", id="app-editor-save", variant="success")
                yield Button("Close", id="app-editor-close")

    def on_mount(self) -> None:
        self.query_one("#app-editor-secrets", TextArea).focus()

    def action_save(self) -> None:
        secrets = self.query_one("#app-editor-secrets", TextArea).text
        env_text = self.query_one("#app-editor-env", TextArea).text
        try:
            message = self.saver(secrets, env_text)
        except Exception as exc:
            self.notify(str(exc), title="Save failed", severity="error")
            return
        self.notify("Application settings saved.", title="Saved", severity="information")
        self.dismiss()
        self.app.call_after_refresh(self.app._write_output_lines, "Application Settings", message.splitlines())

    def action_cancel(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#app-editor-save")
    def _save_pressed(self) -> None:
        self.action_save()

    @on(Button.Pressed, "#app-editor-close")
    def _close_pressed(self) -> None:
        self.action_cancel()


class InteractiveDashboardApp(App[dict[str, Any]]):
    CSS = """
    Screen {
        layout: vertical;
    }

    #body {
        layout: horizontal;
        height: 1fr;
    }

    #sidebar {
        width: 32;
        border: round $accent;
        padding: 0 1;
    }

    #main-pane {
        border: round $primary;
        padding: 0 1;
    }

    .pane-title {
        color: $accent;
        height: 1;
        margin: 0 0 1 0;
    }

    #actions {
        height: 10;
        border: solid $panel-lighten-2;
        margin: 0 0 1 0;
    }

    #target-filter {
        margin: 0 0 1 0;
    }

    #targets {
        height: 1fr;
        border: solid $panel-lighten-2;
    }

    #output {
        height: 1fr;
        border: solid $panel-lighten-2;
        margin: 0 0 1 0;
    }

    #details {
        height: 11;
        border: solid $panel-lighten-2;
        padding: 0 1;
    }

    #inventory-editor, #app-editor {
        width: 90%;
        height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }

    #inventory-editor-text, #app-editor-secrets, #app-editor-env {
        height: 1fr;
        border: solid $panel-lighten-2;
        margin: 0 0 1 0;
    }

    #inventory-editor-help, #app-editor-help {
        margin: 0 0 1 0;
    }

    #inventory-editor-buttons, #app-editor-buttons {
        height: 3;
        align: right middle;
    }
    """

    BINDINGS = [
        Binding("q", "quit_dashboard", "Quit"),
        Binding("ctrl+r", "run_selected", "Run"),
        Binding("f6", "focus_actions", "Actions"),
        Binding("f7", "focus_targets", "Targets"),
    ]

    def __init__(
        self,
        *,
        inline_handlers: dict[str, InlineHandler] | None = None,
        setup_defaults: dict[str, Any] | None = None,
        target_items: list[str] | None = None,
        target_item_handler: TargetItemHandler | None = None,
        inventory_settings_text: str = "",
        inventory_settings_saver: InventoryEditorSaver | None = None,
        app_secrets_text: str = "",
        app_env_text: str = "",
        app_settings_saver: AppEditorSaver | None = None,
    ) -> None:
        super().__init__()
        self.inline_handlers = inline_handlers or {}
        self.setup_defaults = setup_defaults or {}
        self.target_items = target_items or []
        self.target_item_handler = target_item_handler
        self.inventory_settings_text = inventory_settings_text
        self.inventory_settings_saver = inventory_settings_saver
        self.app_secrets_text = app_secrets_text
        self.app_env_text = app_env_text
        self.app_settings_saver = app_settings_saver
        self.target_filter = ""
        self.selection = InteractiveSelection()
        self.output_payload = OutputPayload(title="Output")
        self.background_thread: threading.Thread | None = None
        self.pending_selection: InteractiveSelection | None = None
        self.run_started_at = 0.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("Actions", classes="pane-title")
                yield ListView(id="actions")
                yield Static("Targets", classes="pane-title")
                yield Input(placeholder="Filter target IPs", id="target-filter")
                yield ListView(id="targets")
            with Vertical(id="main-pane"):
                yield Static("Output", id="output-title", classes="pane-title")
                yield RichLog(id="output", wrap=False, highlight=False, markup=False, auto_scroll=False)
                yield Static("Details", classes="pane-title")
                yield Static("", id="details")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_actions()
        self._populate_targets()
        self._show_welcome()
        self._refresh_details()
        self.set_interval(0.5, self._refresh_runtime_status)
        self.query_one("#actions", ListView).focus()

    def _populate_actions(self) -> None:
        actions = self.query_one("#actions", ListView)
        actions.clear()
        for label, action in ACTION_LABELS:
            actions.append(ActionListItem(label, action))

    def _populate_targets(self) -> None:
        targets = self.query_one("#targets", ListView)
        targets.clear()
        for ip in self._filtered_targets():
            targets.append(TargetListItem(ip))

    def _filtered_targets(self) -> list[str]:
        if not self.target_filter:
            return list(self.target_items)
        needle = self.target_filter.lower()
        return [ip for ip in self.target_items if needle in ip.lower()]

    def _selected_action_item(self) -> ActionListItem:
        actions = self.query_one("#actions", ListView)
        item = actions.highlighted_child
        if isinstance(item, ActionListItem):
            return item
        return ActionListItem(*ACTION_LABELS[0])

    def _selected_target(self) -> str:
        targets = self.query_one("#targets", ListView)
        item = targets.highlighted_child
        if isinstance(item, TargetListItem):
            return item.ip
        return ""

    def _show_welcome(self) -> None:
        self._write_output_lines(
            "Output",
            [
                "Textual interactive dashboard is ready.",
                "",
                "Use the left pane to choose an action and a target.",
                "Press Enter on an action, or Ctrl+R, to execute it.",
                "Press Enter on a target to run single-device audit.",
            ],
        )

    def _write_output_lines(self, title: str, lines: list[str]) -> None:
        self.query_one("#output-title", Static).update(title)
        output = self.query_one("#output", RichLog)
        output.clear()
        for line in lines or ["<empty>"]:
            output.write(line)

    def _load_output_payload(self, payload: OutputPayload) -> None:
        lines: list[str] = []
        if payload.summary_lines:
            lines.extend(payload.summary_lines)
        if payload.text:
            if lines:
                lines.append("")
            lines.extend(payload.text.splitlines())
        if payload.list_items:
            if lines:
                lines.append("")
            if payload.list_title:
                lines.append(payload.list_title)
            lines.extend(payload.list_items)
        self._write_output_lines(payload.title, lines or ["<empty>"])

    def _refresh_details(self) -> None:
        action_item = self._selected_action_item()
        target = self._selected_target() or "<none>"
        running = self.background_thread is not None
        elapsed = time.time() - self.run_started_at if self.run_started_at else 0.0

        lines = [
            f"Selected action: {action_item.label_text}",
            f"Action id: {action_item.action}",
            f"Selected target: {target}",
            "",
        ]

        action = action_item.action
        if action == "audit_full":
            lines.append("Runs a full audit against the inventory target set.")
        elif action == "audit_single":
            lines.append("Runs single-device audit for the selected target.")
        elif action == "generate_script":
            lines.append("Generates a remediation script for the selected target.")
        elif action == "remediate":
            lines.append("Runs dry-run remediation for all supported domains.")
        elif action == "phpipam_report":
            lines.append("Builds the phpIPAM comparison report.")
        elif action == "targets":
            lines.append("Shows resolved inventory targets in the output pane.")
        elif action == "app_settings":
            lines.append("Shows effective application settings loaded from env/files.")
        elif action == "inventory_settings":
            lines.append("Shows inventory YAML settings used by the audit workflow.")
        elif action == "doctor":
            lines.append("Runs local environment and settings checks.")
        elif action == "quit":
            lines.append("Exit interactive mode.")

        lines.extend(
            [
                "",
                "Keys",
                "Enter on Actions: run selected action",
                "Enter on Targets: single-device audit",
                "r on Targets: dry-run remediation",
                "g on Targets: generate script",
                "q: quit",
                "",
                f"Status: {'running' if running else 'idle'}",
            ]
        )
        if running:
            lines.append(f"Elapsed: {elapsed:.1f}s")

        self.query_one("#details", Static).update("\n".join(lines))

    def _refresh_runtime_status(self) -> None:
        self._refresh_details()

    def _build_selection(self, action: str) -> InteractiveSelection | None:
        if action in {"audit_full", "phpipam_report", "targets", "doctor"}:
            return InteractiveSelection(action=action)
        if action == "quit":
            return InteractiveSelection(action="quit", confirmed=True)

        ip = self._selected_target().strip()
        if not ip:
            self.notify("Select a target IP first.", title="Missing target", severity="warning")
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.notify(f"Selected value is not a valid IP: {ip}", title="Invalid target", severity="error")
            return None

        if action == "audit_single":
            return InteractiveSelection(action=action, ip=ip, export=False)
        if action == "generate_script":
            return InteractiveSelection(action=action, ip=ip)
        if action == "remediate":
            return InteractiveSelection(
                action=action,
                ip=ip,
                apply=False,
                remediation_domains=list(REMEDIATION_DOMAINS),
            )
        return None

    def _open_inventory_settings_editor(self) -> None:
        if self.inventory_settings_saver is None:
            self.notify("Inventory settings saver is not configured.", title="Unavailable", severity="error")
            return
        self.push_screen(
            InventoryEditorScreen(
                initial_text=self.inventory_settings_text,
                saver=self._save_inventory_settings,
            )
        )

    def _open_app_settings_editor(self) -> None:
        if self.app_settings_saver is None:
            self.notify("Application settings saver is not configured.", title="Unavailable", severity="error")
            return
        self.push_screen(
            AppSettingsEditorScreen(
                secrets_text=self.app_secrets_text,
                env_text=self.app_env_text,
                saver=self._save_app_settings,
            )
        )

    def _save_inventory_settings(self, text: str) -> str:
        if self.inventory_settings_saver is None:
            raise RuntimeError("Inventory settings saver is not configured.")
        message = self.inventory_settings_saver(text)
        self.inventory_settings_text = text
        return message

    def _save_app_settings(self, secrets_text: str, env_text: str) -> str:
        if self.app_settings_saver is None:
            raise RuntimeError("Application settings saver is not configured.")
        message = self.app_settings_saver(secrets_text, env_text)
        self.app_secrets_text = secrets_text
        self.app_env_text = env_text
        return message

    def _start_action(self, selection: InteractiveSelection) -> None:
        if self.background_thread is not None:
            self.notify("Another action is still running.", title="Busy", severity="warning")
            return

        self.selection = selection
        self.pending_selection = selection
        self.run_started_at = time.time()
        self._write_output_lines(
            f"Running: {selection.action}",
            [
                f"Started action: {selection.action}",
                f"Target: {selection.ip or '<inventory target set>'}",
                "",
                "Please wait. Output will be written here automatically.",
            ],
        )

        worker = threading.Thread(
            target=self._run_background_action,
            name="textual-interactive-worker",
            daemon=True,
        )
        self.background_thread = worker
        worker.start()
        self._refresh_details()

    def _run_background_action(self) -> None:
        selection = self.pending_selection or InteractiveSelection(action="quit")
        try:
            handler = self.inline_handlers.get(selection.action)
            if handler is None:
                payload = OutputPayload(
                    title="Execution Error",
                    text=f"No inline handler configured for action: {selection.action}",
                )
            else:
                payload = handler(selection)
        except Exception:
            payload = OutputPayload(
                title="Execution Error",
                text=traceback.format_exc(),
            )
        self.call_from_thread(self._finish_action, payload)

    def _finish_action(self, payload: OutputPayload) -> None:
        self.output_payload = payload
        self.background_thread = None
        self.pending_selection = None
        self.run_started_at = 0.0
        self._load_output_payload(payload)
        self._refresh_details()

    def run_selected_action(self) -> None:
        action = self._selected_action_item().action
        if action == "inventory_settings":
            self._open_inventory_settings_editor()
            return
        if action == "app_settings":
            self._open_app_settings_editor()
            return
        selection = self._build_selection(action)
        if selection is None:
            self._refresh_details()
            return
        if action == "quit":
            self.selection = selection
            self.exit(selection.to_dict())
            return
        self._start_action(selection)

    def run_target_action(self, action: str) -> None:
        selection = self._build_selection(action)
        if selection is None:
            self._refresh_details()
            return
        self._start_action(selection)

    @on(Input.Changed, "#target-filter")
    def _on_target_filter_changed(self, event: Input.Changed) -> None:
        self.target_filter = event.value.strip()
        self._populate_targets()
        self._refresh_details()

    @on(ListView.Highlighted, "#actions")
    def _on_actions_highlighted(self, _event: ListView.Highlighted) -> None:
        self._refresh_details()

    @on(ListView.Highlighted, "#targets")
    def _on_targets_highlighted(self, _event: ListView.Highlighted) -> None:
        self._refresh_details()

    @on(ListView.Selected, "#actions")
    def _on_action_selected(self, _event: ListView.Selected) -> None:
        self.run_selected_action()

    @on(ListView.Selected, "#targets")
    def _on_target_selected(self, _event: ListView.Selected) -> None:
        self.run_target_action("audit_single")

    def action_quit_dashboard(self) -> None:
        selection = InteractiveSelection(action="quit", confirmed=True)
        self.selection = selection
        self.exit(selection.to_dict())

    def action_run_selected(self) -> None:
        self.run_selected_action()

    def action_focus_actions(self) -> None:
        self.query_one("#actions", ListView).focus()

    def action_focus_targets(self) -> None:
        self.query_one("#targets", ListView).focus()


def run_interactive_ui(
    *,
    inline_handlers: dict[str, InlineHandler] | None = None,
    setup_defaults: dict[str, Any] | None = None,
    target_items: list[str] | None = None,
    target_item_handler: TargetItemHandler | None = None,
    inventory_settings_text: str = "",
    inventory_settings_saver: InventoryEditorSaver | None = None,
    app_secrets_text: str = "",
    app_env_text: str = "",
    app_settings_saver: AppEditorSaver | None = None,
) -> dict[str, Any]:
    app = InteractiveDashboardApp(
        inline_handlers=inline_handlers,
        setup_defaults=setup_defaults,
        target_items=target_items,
        target_item_handler=target_item_handler,
        inventory_settings_text=inventory_settings_text,
        inventory_settings_saver=inventory_settings_saver,
        app_secrets_text=app_secrets_text,
        app_env_text=app_env_text,
        app_settings_saver=app_settings_saver,
    )
    result = app.run()
    if isinstance(result, dict):
        return result
    return InteractiveSelection(action="quit", confirmed=True).to_dict()
