"""Desktop GUI for OSINT Agent."""

from __future__ import annotations

import json
import os
import sys
import time
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse

import yaml
from PySide6.QtCore import QEvent, QProcess, QSize, QSettings, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QKeySequence, QPalette, QShortcut
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gui.graph import build_display_graph, render_attack_html, render_gravis_html
from actions import ActionRegistry
from agents import get_llm_config
from core.keyvault import KEY_SPECS, KeyVault
from modules import MODULE_REGISTRY, get_all_module_ids
from tools.external import (
    DOCKER_TOOLS,
    configure_tool_backend,
    tool_available,
)
from tools.tool_manager import TOOL_DEFINITIONS


# Container-only tools (baked into docker/Dockerfile.tools) that have no
# TOOL_DEFINITIONS entry. Shown in Settings → Tools so operators see the
# full container toolchain, not just the host-installable subset.
EXTRA_CONTAINER_TOOLS: dict[str, tuple[list[str], str]] = {
    "jsluice": (["web", "js", "endpoints"], "JS endpoint and secret extraction (Tier-1)"),
    "gxss": (["web", "xss", "param"], "Reflect candidate parameters for XSS (Tier-1)"),
    "uro": (["web", "dedup"], "URL dedup and normalisation for fuzz lists (Tier-1)"),
    "graphql-cop": (["web", "graphql"], "GraphQL security tester (Tier-1)"),
    "interactsh-client": (["oob", "callback"], "Free OOB callbacks via public interactsh"),
    "kr": (["web", "api", "fuzzing"], "API route brute force, assetnote wordlists (Tier-2)"),
    "semgrep": (["web", "sast", "js"], "SAST over JS bundles, repo-local rules (Tier-2)"),
    "gobuster": (["web", "fuzzing"], "Directory and DNS brute-forcer"),
    "feroxbuster": (["web", "fuzzing"], "Recursive content discovery"),
    "assetfinder": (["dns", "subdomain"], "Subdomain discovery via public sources"),
    "waybackurls": (["web", "recon"], "Historic URLs from the Wayback Machine"),
    "subzy": (["dns", "takeover"], "Subdomain takeover checker"),
    "dig": (["dns", "probe"], "DNS lookup utility"),
    "whois": (["recon", "whois"], "Domain registration lookup"),
}


ROOT_DIR = Path(__file__).resolve().parent.parent
ORCHESTRATOR = ROOT_DIR / "orchestrator.py"
TOOLS_REQUIREMENTS = ROOT_DIR / "tools_requirements.txt"

STATUS_COLORS = {
    "completed": "#4ade80",
    "complete": "#4ade80",
    "running": "#7dd3fc",
    "timeout": "#fbbf24",
    "incomplete": "#fbbf24",
    "error": "#f87171",
    "failed": "#f87171",
    "blocked": "#fb923c",
    "skipped": "#94a3b8",
}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#fb7185",
    "HIGH": "#fdba74",
    "MEDIUM": "#fde047",
    "LOW": "#93c5fd",
    "INFO": "#94a3b8",
}
CONFIDENCE_RANK = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}

EMPTY_GRAPH_HTML = (
    "<html><body style='font-family:Arial;background:#090d13;padding:24px;"
    "color:#dce7f3;'>{message}</body></html>"
)
VERDICT_LABELS = {
    "": "-",
    "true_positive": "true positive",
    "false_positive": "false positive",
    "out_of_scope": "out of scope",
}
VERDICT_COLORS = {
    "true_positive": "#4ade80",
    "false_positive": "#f87171",
    "out_of_scope": "#fbbf24",
}


def _priority_rank(priority: str) -> int:
    """P0 sorts first; anything unparseable sinks to the bottom."""
    text = str(priority or "").strip().upper()
    if text.startswith("P") and text[1:].isdigit():
        return int(text[1:])
    return 99


def _bold_font() -> QFont:
    font = QFont()
    font.setBold(True)
    return font


def code_font(size: int = 12) -> QFont:
    """Monospace font stack that exists on macOS, Linux, and Windows."""
    font = QFont()
    font.setFamilies(["SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", "monospace"])
    font.setPointSize(size)
    return font


def _dark_palette() -> QPalette:
    """Dark Fusion palette.

    Stylesheets do not cover every paint path — the tab-bar base line,
    scroll-area corners and disabled texts still read the app palette, which
    defaults to the light system theme and leaks white lines into the UI.
    """
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#101721"))
    palette.setColor(QPalette.WindowText, QColor("#dce7f3"))
    palette.setColor(QPalette.Base, QColor("#0b111a"))
    palette.setColor(QPalette.AlternateBase, QColor("#0d1420"))
    palette.setColor(QPalette.ToolTipBase, QColor("#151f2e"))
    palette.setColor(QPalette.ToolTipText, QColor("#e5edf6"))
    palette.setColor(QPalette.Text, QColor("#e5edf6"))
    palette.setColor(QPalette.Button, QColor("#151f2e"))
    palette.setColor(QPalette.ButtonText, QColor("#dce7f3"))
    palette.setColor(QPalette.BrightText, QColor("#f87171"))
    palette.setColor(QPalette.Link, QColor("#7dd3fc"))
    palette.setColor(QPalette.LinkVisited, QColor("#93c5fd"))
    palette.setColor(QPalette.Highlight, QColor("#9f1239"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    # Grayscale roles: QStyle frame/base lines (tab-bar base, scroll corners)
    # read Light/Mid/Dark and would otherwise stay light-theme white.
    palette.setColor(QPalette.Light, QColor("#3b5675"))
    palette.setColor(QPalette.Midlight, QColor("#2b3c54"))
    palette.setColor(QPalette.Mid, QColor("#223044"))
    palette.setColor(QPalette.Dark, QColor("#172233"))
    palette.setColor(QPalette.Shadow, QColor("#000000"))
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor("#5b6a80"))
    return palette


def build_scan_args(
    target: str,
    output_dir: Path | str,
    config_path: Path | str,
    mode: str = "Auto",
    active: bool = False,
    module: str | None = None,
    pentest: bool = False,
    execute: bool = False,
    max_risk: str = "LOW",
    max_actions: int = 25,
    max_chains: int = 10,
) -> list[str]:
    """Build orchestrator argv for a GUI run.

    Kept as a pure function so tests can assert every console control reaches
    the CLI. `-c` is always passed because Settings writes config.yaml at a
    path the orchestrator would otherwise never read (it resolves a relative
    default against the process CWD, which is the repo root we also pin in
    ``_start_process``).
    """
    args = [
        str(ORCHESTRATOR),
        "-t", target,
        "-o", str(output_dir),
        "-c", str(config_path),
    ]
    if active:
        args.append("--active")
    # Independent of `active`: both flags may legitimately apply at once.
    if mode == "LLM":
        args.extend(["--mode", "llm"])
    if module:
        args.extend(["--module", str(module)])
    if pentest:
        args.append("--pentest")
        args.extend(["--max-risk", str(max_risk)])
        args.extend(["--max-actions", str(int(max_actions))])
        args.extend(["--max-chains", str(int(max_chains))])
        if execute:
            args.append("--execute")
    return args


class MainWindow(QMainWindow):
    SCREEN_DEFS = [
        ("run", "Run", QStyle.SP_MediaPlay,
         "Control room: mission setup, run controls, live log"),
        ("triage", "Triage", QStyle.SP_DialogApplyButton,
         "Findings triage: filters, verdicts, detail pane"),
        ("graph", "Graph", QStyle.SP_ComputerIcon,
         "Asset graph and attack graph with probe plan"),
        ("data", "Data", QStyle.SP_DirIcon,
         "Assets, modules, evidence and submissions"),
        ("report", "Report", QStyle.SP_FileIcon,
         "Report, attack plan and summary JSON"),
        ("settings", "Settings", QStyle.SP_FileDialogDetailedView,
         "LLM, runtime, scanner, tools and config editor"),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Agent")
        self._settings = QSettings("osintAgent", "gui")
        self.process: QProcess | None = None
        self.running_report = False
        self.report_after_process = False
        self.current_assets = {"nodes": [], "edges": []}
        self.current_module = {}
        self.current_evidence = {"items": []}
        self.current_findings: list[dict] = []
        self.current_attack_graph: dict = {}
        self._identity_records: list[dict] = []
        self._triage: dict = {}
        self._findings_sort: list = [3, Qt.DescendingOrder]
        self._filtered_findings: list[dict] = []
        self.output_dir = ROOT_DIR / "reports"
        self.config_path = ROOT_DIR / "config.yaml"
        self._run_started_at: float | None = None
        # Timers exist before _build_ui so signal wiring in it is safe.
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._tick_run_progress)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(750)
        self._poll_timer.timeout.connect(self._poll_run_state)
        # Debounced reload: typing a target must not re-read disk per keystroke.
        self._target_reload_timer = QTimer(self)
        self._target_reload_timer.setSingleShot(True)
        self._target_reload_timer.setInterval(600)
        self._target_reload_timer.timeout.connect(self.load_results)
        self._build_ui()
        self.target_input.textChanged.connect(
            lambda *_: self._target_reload_timer.start()
        )
        self._restore_window_state()
        self._apply_style()
        self._load_settings_form()
        self._refresh_module_list()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._prefer_llm_if_ready()
        self._update_operation_context()
        # First window of a session opens on data, not on empty widgets.
        last_target = self._settings.value("target", "", type=str)
        if last_target:
            self.target_input.setText(last_target)
        try:
            self.load_results()
        except Exception:
            pass  # a corrupt state file must never block startup
        self._target_reload_timer.stop()

    def _restore_window_state(self):
        geometry = self._settings.value("geometry")
        if geometry is not None:
            try:
                self.restoreGeometry(geometry)
            except TypeError:
                self.resize(1280, 820)
        else:
            self.resize(1280, 820)
        self.setMinimumSize(1100, 720)
        screen = self._settings.value("screen", 0, type=int)
        self.show_screen(screen if isinstance(screen, int) else 0)

    def closeEvent(self, event):
        # A closing window must cancel pending work: the debounced target
        # reload would otherwise fire from a hidden window long after close.
        self._target_reload_timer.stop()
        self._elapsed_timer.stop()
        self._poll_timer.stop()
        # Offscreen (test) runs must not clobber the operator's saved layout.
        if os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            self._settings.setValue("geometry", self.saveGeometry())
            self._settings.setValue(
                "target", self.target_input.text().strip()
            )
            if hasattr(self, "screen_stack"):
                self._settings.setValue("screen", self.screen_stack.currentIndex())
        super().closeEvent(event)

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)
        title_stack = QVBoxLayout()
        title = QLabel("RED TEAM OPS CONSOLE")
        title.setObjectName("title")
        subtitle = QLabel("OSINT collection, exposure mapping, evidence handling")
        subtitle.setObjectName("subtitle")
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        header.addLayout(title_stack)

        self.config_chip = QLabel(self.config_path.name)
        self.config_chip.setObjectName("contextChip")
        self.config_chip.setToolTip(str(self.config_path))
        self.output_chip = QLabel(self._display_path(self.output_dir, 3))
        self.output_chip.setObjectName("contextChip")
        self.output_chip.setToolTip(str(self.output_dir))
        header.addSpacing(8)
        header.addWidget(self.config_chip)
        header.addWidget(self.output_chip)
        header.addStretch(1)

        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("status")
        self.status_label.setProperty("state", "idle")
        header.addWidget(self.status_label)
        layout.addLayout(header)

        body = QHBoxLayout()
        body.setSpacing(12)
        body.addWidget(self._build_nav_rail())

        self.screen_stack = QStackedWidget()
        self.screen_stack.setObjectName("screenStack")
        # Build order must match SCREEN_DEFS (rail index == stack index).
        self.screen_stack.addWidget(self._build_run_screen())
        self.screen_stack.addWidget(self._build_triage_screen())
        self.screen_stack.addWidget(self._build_graph_screen())
        self.screen_stack.addWidget(self._build_data_screen())
        self.screen_stack.addWidget(self._build_report_screen())
        self.screen_stack.addWidget(self._build_settings_panel())
        body.addWidget(self.screen_stack, 1)
        layout.addLayout(body, 1)

        self.status_bar_label = QLabel("")
        self.status_bar_label.setObjectName("statusBarLabel")
        self.statusBar().addWidget(self.status_bar_label, 1)

        self.setCentralWidget(root)
        self._build_menu()

    def _build_nav_rail(self) -> QWidget:
        rail = QWidget()
        rail.setObjectName("navRail")
        rail.setFixedWidth(78)
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(6, 8, 6, 8)
        rail_layout.setSpacing(4)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: list[QToolButton] = []
        for index, (_key, label, icon, tip) in enumerate(self.SCREEN_DEFS):
            button = QToolButton()
            button.setObjectName("navButton")
            button.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            button.setCheckable(True)
            button.setAutoRaise(True)
            button.setIcon(self.style().standardIcon(icon))
            button.setIconSize(QSize(20, 20))
            button.setText(label)
            button.setToolTip(f"{tip}  (Ctrl+{index + 1})")
            button.setFixedSize(66, 60)
            button.clicked.connect(lambda _checked=False, i=index: self.show_screen(i))
            self.nav_group.addButton(button, index)
            self.nav_buttons.append(button)
            rail_layout.addWidget(button)
        rail_layout.addStretch(1)
        if self.nav_buttons:
            self.nav_buttons[0].setChecked(True)
        return rail

    def show_screen(self, index: int) -> None:
        """Switch the stacked screen and keep rail, stack and settings in sync."""
        if not 0 <= index < self.screen_stack.count():
            return
        self.screen_stack.setCurrentIndex(index)
        if index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)
        self._settings.setValue("screen", index)

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("File")
        open_output = QAction("Choose Output Directory", self)
        open_output.triggered.connect(self.choose_output_dir)
        file_menu.addAction(open_output)

        use_config = QAction("Use Config File...", self)
        use_config.setShortcut(QKeySequence("Ctrl+O"))
        use_config.triggered.connect(self.choose_config_file)
        file_menu.addAction(use_config)

        open_target = QAction("Open Target Folder", self)
        open_target.triggered.connect(self.open_target_folder)
        file_menu.addAction(open_target)

        reload_report = QAction("Reload Current Results", self)
        reload_report.setShortcuts([QKeySequence("F5"), QKeySequence("Ctrl+R")])
        reload_report.triggered.connect(self.load_results)
        file_menu.addAction(reload_report)

        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        operation_menu = self.menuBar().addMenu("Operation")
        run_action = QAction("Run", self)
        run_action.setShortcut(QKeySequence("Ctrl+Return"))
        run_action.triggered.connect(self.start_scan)
        operation_menu.addAction(run_action)

        stop_action = QAction("Stop", self)
        stop_action.triggered.connect(self.stop_scan)
        operation_menu.addAction(stop_action)

        report_action = QAction("Generate Report", self)
        report_action.triggered.connect(self.generate_report)
        operation_menu.addAction(report_action)

        settings_menu = self.menuBar().addMenu("Settings")
        reload_settings = QAction("Reload Config", self)
        reload_settings.triggered.connect(self._load_settings_form)
        settings_menu.addAction(reload_settings)

        save_settings = QAction("Save Config", self)
        save_settings.triggered.connect(self._save_settings_form)
        settings_menu.addAction(save_settings)

        # Ctrl+1..6 jump straight to a screen (the rail's tooltip order).
        for index in range(len(self.SCREEN_DEFS)):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self)
            shortcut.setContext(Qt.ApplicationShortcut)
            shortcut.activated.connect(lambda i=index: self.show_screen(i))

    def _build_controls(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(0)
        layout = QVBoxLayout(panel)
        layout.setSpacing(12)

        target_box = QGroupBox("Mission Setup")
        form = QFormLayout(target_box)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.target_input = QLineEdit("get-ads.agency")
        self.target_input.setPlaceholderText("example.com")
        # Enter in the target field is the classic "just run it" gesture.
        self.target_input.returnPressed.connect(self.start_scan)
        self.target_input.setMinimumWidth(0)
        self.target_input.textChanged.connect(self._update_operation_context)
        self.output_input = QLineEdit(str(self.output_dir))
        self.output_input.setReadOnly(True)
        self.output_input.setMinimumWidth(0)
        self.output_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        choose_output = QPushButton("Browse")
        choose_output.clicked.connect(self.choose_output_dir)
        output_row = QHBoxLayout()
        output_row.setContentsMargins(0, 0, 0, 0)
        output_row.addWidget(self.output_input, 1)
        output_row.addWidget(choose_output)
        form.addRow("Target", self.target_input)
        form.addRow("Output", output_row)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Auto", "LLM", "Single module"])
        self.mode_combo.setMinimumWidth(0)
        self.mode_combo.setToolTip(
            "Auto: run active modules. LLM: AI-guided run. "
            "Single module: only the module selected below."
        )
        self.mode_combo.currentIndexChanged.connect(self._sync_mode)
        self.mode_combo.currentIndexChanged.connect(self._update_operation_context)
        self.stage_filter_combo = QComboBox()
        self.stage_filter_combo.setMinimumWidth(0)
        self.stage_filter_combo.addItem("All stages", 0)
        for stage in range(1, 7):
            self.stage_filter_combo.addItem(f"Stage {stage}", stage)
        self.stage_filter_combo.setToolTip(
            "Restrict the module list (and Auto runs) to one pipeline stage."
        )
        self.stage_filter_combo.currentIndexChanged.connect(self._refresh_module_list)
        self.module_combo = QComboBox()
        self.module_combo.setMinimumWidth(0)
        self.module_combo.setToolTip(
            "Used by Single module mode and by the plan/probe actions."
        )
        self.module_combo.currentIndexChanged.connect(self._update_module_hint)
        self.module_combo.currentIndexChanged.connect(self._update_operation_context)
        self.module_hint = QLabel("-")
        self.module_hint.setWordWrap(True)
        self.active_check = QCheckBox("Active mode")
        self.auto_report_check = QCheckBox("Generate report after run")
        self.auto_report_check.setChecked(True)
        form.addRow("Mode", self.mode_combo)
        form.addRow("Stage", self.stage_filter_combo)
        form.addRow("Module", self.module_combo)
        form.addRow("Info", self.module_hint)
        form.addRow("", self.active_check)
        form.addRow("", self.auto_report_check)
        layout.addWidget(target_box)

        engage_box = QGroupBox("Engagement")
        engage_form = QFormLayout(engage_box)
        engage_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.pentest_check = QCheckBox("Attack graph + probe plan (--pentest)")
        self.execute_check = QCheckBox("Execute proposed chains (--execute)")
        self.execute_check.setEnabled(False)
        self.pentest_check.toggled.connect(self.execute_check.setEnabled)
        self.pentest_check.toggled.connect(self._update_operation_context)
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["SAFE", "LOW", "MEDIUM", "HIGH", "DESTRUCTIVE"])
        self.risk_combo.setCurrentText("LOW")
        self.risk_combo.setMinimumWidth(0)
        self.risk_combo.setToolTip(
            "Highest action risk the AI attack plan may propose (pentest mode)."
        )
        self.max_actions_spin = QSpinBox()
        self.max_actions_spin.setRange(0, 1000)
        self.max_actions_spin.setValue(25)
        self.max_chains_spin = QSpinBox()
        self.max_chains_spin.setRange(0, 1000)
        self.max_chains_spin.setValue(10)
        engage_form.addRow("", self.pentest_check)
        engage_form.addRow("", self.execute_check)
        engage_form.addRow("Risk ceiling", self.risk_combo)
        engage_form.addRow("Max actions", self.max_actions_spin)
        engage_form.addRow("Max chains", self.max_chains_spin)
        layout.addWidget(engage_box)

        ai_box = QGroupBox("AI Assist")
        ai_layout = QVBoxLayout(ai_box)
        self.llm_status_label = QLabel("LLM status: checking")
        self.llm_status_label.setWordWrap(True)
        self.llm_status_label.setObjectName("assistantStatus")
        self.llm_status_label.setMinimumWidth(0)
        self.ai_run_button = QPushButton("AI Guided Run")
        self.ai_run_button.setObjectName("btnPrimary")
        self.ai_run_button.clicked.connect(self.start_llm_scan)
        self.ai_plan_button = QPushButton("AI Attack Plan")
        self.ai_plan_button.setObjectName("btnPrimary")
        self.ai_plan_button.clicked.connect(self.generate_attack_plan)
        ai_layout.addWidget(self.llm_status_label)
        ai_layout.addWidget(self.ai_run_button)
        ai_layout.addWidget(self.ai_plan_button)
        layout.addWidget(ai_box)

        action_box = QGroupBox("Execution Controls")
        action_layout = QGridLayout(action_box)
        self.run_button = QPushButton("Run")
        self.run_button.setObjectName("btnPrimary")
        self.run_button.setDefault(True)
        self.run_button.setAutoDefault(True)
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("btnDanger")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.reload_button = QPushButton("Reload")
        self.reload_button.clicked.connect(self.load_results)
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.log_output.clear)
        self.generate_report_button = QPushButton("Report")
        self.generate_report_button.setObjectName("btnPrimary")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.prioritize_button = QPushButton("Prioritize")
        self.prioritize_button.clicked.connect(self.prioritize_findings)
        self.submission_button = QPushButton("Submissions")
        self.submission_button.clicked.connect(self.generate_submissions)
        self.open_report_button = QPushButton("Open")
        self.open_report_button.clicked.connect(self.open_report)
        self.open_folder_button = QPushButton("Folder")
        self.open_folder_button.clicked.connect(self.open_target_folder)
        action_layout.addWidget(self.run_button, 0, 0)
        action_layout.addWidget(self.stop_button, 0, 1)
        action_layout.addWidget(self.reload_button, 1, 0)
        action_layout.addWidget(self.clear_button, 1, 1)
        action_layout.addWidget(self.generate_report_button, 2, 0)
        action_layout.addWidget(self.prioritize_button, 2, 1)
        action_layout.addWidget(self.submission_button, 3, 0)
        action_layout.addWidget(self.open_report_button, 3, 1)
        action_layout.addWidget(self.open_folder_button, 4, 0, 1, 2)
        layout.addWidget(action_box)

        summary_box = QGroupBox("Operational Telemetry")
        summary_layout = QVBoxLayout(summary_box)
        self.assets_value = QLabel("-")
        self.relations_value = QLabel("-")
        self.findings_value = QLabel("-")
        self.evidence_value = QLabel("-")
        self.max_risk_value = QLabel("-")
        self.critical_high_value = QLabel("-")
        self.requests_value = QLabel("-")
        self.completed_value = QLabel("-")
        self.skipped_value = QLabel("-")
        self.incomplete_value = QLabel("-")
        self.blocked_value = QLabel("-")
        self.active_value = QLabel("-")
        self.report_value = QLabel("-")
        self.report_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_value.setWordWrap(True)
        self.report_value.setMinimumWidth(0)
        metrics_grid = QGridLayout()
        metric_cards = [
            ("Assets", self.assets_value, "info"),
            ("Relations", self.relations_value, "info"),
            ("Findings", self.findings_value, "warning"),
            ("Evidence", self.evidence_value, "success"),
            ("Max Risk", self.max_risk_value, "danger"),
            ("Crit/High", self.critical_high_value, "danger"),
            ("Requests", self.requests_value, "info"),
            ("Complete", self.completed_value, "success"),
            ("Incomplete", self.incomplete_value, "danger"),
        ]
        for index, (label, value_label, tone) in enumerate(metric_cards):
            metrics_grid.addWidget(self._metric_card(label, value_label, tone), index // 2, index % 2)
        summary_layout.addLayout(metrics_grid)
        secondary_layout = QFormLayout()
        secondary_layout.addRow("Skipped", self.skipped_value)
        secondary_layout.addRow("Blocked", self.blocked_value)
        secondary_layout.addRow("Active modules", self.active_value)
        secondary_layout.addRow("Report", self.report_value)
        summary_layout.addLayout(secondary_layout)
        layout.addWidget(summary_box)

        layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setObjectName("sideScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(panel)
        scroll.setMinimumWidth(300)
        scroll.setMaximumWidth(460)
        scroll.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        return scroll

    def _build_settings_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        settings_tabs = QTabWidget()
        settings_tabs.setDocumentMode(True)
        settings_tabs.tabBar().setUsesScrollButtons(True)
        # Fusion draws CE_TabBarBase with the light palette — a stray white
        # line across the strip; we style the pane border instead.
        settings_tabs.tabBar().setDrawBase(False)
        settings_tabs.addTab(self._build_llm_settings_tab(), "LLM")
        settings_tabs.addTab(self._build_runtime_settings_tab(), "Runtime")
        settings_tabs.addTab(self._build_scanner_settings_tab(), "Scanner")
        settings_tabs.addTab(self._build_actions_settings_tab(), "Actions")
        settings_tabs.addTab(self._build_tools_settings_tab(), "Tools")
        settings_tabs.addTab(self._build_keys_settings_tab(), "API Keys")
        settings_tabs.addTab(self._build_raw_config_tab(), "Raw YAML")
        layout.addWidget(settings_tabs, 1)
        return panel

    def _build_llm_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        llm_box = QGroupBox("LLM Provider")
        form = QFormLayout(llm_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.llm_model_combo = QComboBox()
        self.llm_model_combo.setEditable(True)
        self.llm_model_combo.addItems([
            "",
            "deepseek/deepseek-chat",
            "deepseek/deepseek-reasoner",
            "openai/gpt-4o",
            "openai/gpt-4.1",
            "openai/o4-mini",
            "anthropic/claude-sonnet-4-20250514",
            "groq/llama-3.3-70b-versatile",
            "openrouter/openai/gpt-4o",
            "ollama/llama3.1",
            "ollama/nemotron-3-super:cloud",
            "lm_studio/local-model",
        ])
        self.llm_model_combo.lineEdit().setPlaceholderText("provider/model or shortcut")
        self.llm_api_key_input = QLineEdit()
        self.llm_api_key_input.setEchoMode(QLineEdit.Password)
        self.llm_api_key_input.setPlaceholderText("Stored in config.yaml; env vars still work")
        self.llm_temperature_spin = QDoubleSpinBox()
        self.llm_temperature_spin.setRange(0.0, 2.0)
        self.llm_temperature_spin.setSingleStep(0.1)
        self.llm_temperature_spin.setDecimals(2)
        self.llm_max_tokens_spin = QSpinBox()
        self.llm_max_tokens_spin.setRange(256, 128000)
        self.llm_max_tokens_spin.setSingleStep(256)
        form.addRow("Model", self.llm_model_combo)
        form.addRow("API key", self.llm_api_key_input)
        form.addRow("Temperature", self.llm_temperature_spin)
        form.addRow("Max tokens", self.llm_max_tokens_spin)
        layout.addWidget(llm_box)

        status_box = QGroupBox("LLM Status")
        status_layout = QVBoxLayout(status_box)
        self.llm_settings_status = QLabel("Not checked")
        self.llm_settings_status.setObjectName("assistantStatus")
        self.llm_settings_status.setWordWrap(True)
        status_layout.addWidget(self.llm_settings_status)
        button_row = QHBoxLayout()
        self.save_llm_button = QPushButton("Save LLM Settings")
        self.save_llm_button.clicked.connect(self._save_settings_form)
        self.reload_llm_button = QPushButton("Reload")
        self.reload_llm_button.clicked.connect(self._load_settings_form)
        self.refresh_llm_status_button = QPushButton("Refresh Status")
        self.refresh_llm_status_button.clicked.connect(self._update_operation_context)
        button_row.addWidget(self.save_llm_button)
        button_row.addWidget(self.reload_llm_button)
        button_row.addWidget(self.refresh_llm_status_button)
        status_layout.addLayout(button_row)
        layout.addWidget(status_box)
        layout.addStretch(1)
        return tab

    def _build_runtime_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        target_box = QGroupBox("Target Defaults")
        target_form = QFormLayout(target_box)
        target_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.config_target_domain_input = QLineEdit()
        self.config_target_domain_input.setPlaceholderText("Default target when CLI does not override")
        self.config_mode_combo = QComboBox()
        self.config_mode_combo.addItems(["passive", "active", "deep"])
        target_form.addRow("Domain", self.config_target_domain_input)
        target_form.addRow("Mode", self.config_mode_combo)
        layout.addWidget(target_box)

        backend_box = QGroupBox("Toolchain Backend")
        backend_form = QFormLayout(backend_box)
        backend_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.tools_backend_combo = QComboBox()
        self.tools_backend_combo.addItems(["local", "docker"])
        self.tools_backend_combo.setToolTip(
            "local: use binaries installed on this machine. "
            "docker: run every baked binary inside the toolchain image "
            "(teammates need only Python + Docker)."
        )
        self.tools_image_input = QLineEdit()
        self.tools_image_input.setPlaceholderText("osint-tools:latest")
        backend_hint = QLabel(
            "Env OSINT_TOOLS_BACKEND / OSINT_TOOLS_IMAGE wins over this file. "
            "Build once: docker build -f docker/Dockerfile.tools -t osint-tools:latest ."
        )
        backend_hint.setWordWrap(True)
        backend_hint.setObjectName("opsSecondary")
        backend_form.addRow("Backend", self.tools_backend_combo)
        backend_form.addRow("Image", self.tools_image_input)
        backend_form.addRow("Note", backend_hint)
        layout.addWidget(backend_box)

        detectability_box = QGroupBox("Detectability")
        detectability_form = QFormLayout(detectability_box)
        self.config_default_detectability_combo = QComboBox()
        self.config_default_detectability_combo.addItems(["low", "medium", "high"])
        detectability_form.addRow("Default", self.config_default_detectability_combo)
        layout.addWidget(detectability_box)

        module_box = QGroupBox("Module Behavior")
        module_form = QFormLayout(module_box)
        self.config_auto_run_check = QCheckBox("Auto-run module chain")
        self.config_record_http_evidence_check = QCheckBox("Record HTTP evidence")
        self.config_max_empty_spin = QSpinBox()
        self.config_max_empty_spin.setRange(0, 100)
        module_form.addRow("", self.config_auto_run_check)
        module_form.addRow("", self.config_record_http_evidence_check)
        module_form.addRow("Max empty modules", self.config_max_empty_spin)
        layout.addWidget(module_box)

        rate_box = QGroupBox("Rate Limits")
        rate_layout = QGridLayout(rate_box)
        rate_layout.addWidget(QLabel("Scope"), 0, 0)
        rate_layout.addWidget(QLabel("Concurrent"), 0, 1)
        rate_layout.addWidget(QLabel("Per minute"), 0, 2)
        self.rate_limit_inputs = {}
        for row, name in enumerate(["default", "dns", "http", "scan"], start=1):
            concurrent = QSpinBox()
            concurrent.setRange(1, 500)
            per_minute = QSpinBox()
            per_minute.setRange(1, 10000)
            self.rate_limit_inputs[name] = {"concurrent": concurrent, "per_minute": per_minute}
            rate_layout.addWidget(QLabel(name), row, 0)
            rate_layout.addWidget(concurrent, row, 1)
            rate_layout.addWidget(per_minute, row, 2)
        layout.addWidget(rate_box)

        limits_box = QGroupBox("Run Limits")
        limits_form = QFormLayout(limits_box)
        limits_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.module_timeout_spin = QSpinBox()
        self.module_timeout_spin.setRange(10, 7200)
        self.module_timeout_spin.setSuffix(" s")
        self.budget_requests_spin = QSpinBox()
        self.budget_requests_spin.setRange(0, 10_000_000)
        self.budget_requests_spin.setSpecialValueText("unlimited")
        self.budget_wall_clock_spin = QSpinBox()
        self.budget_wall_clock_spin.setRange(0, 86400)
        self.budget_wall_clock_spin.setSuffix(" s")
        self.budget_wall_clock_spin.setSpecialValueText("unlimited")
        self.budget_llm_spin = QSpinBox()
        self.budget_llm_spin.setRange(0, 1_000_000)
        self.budget_llm_spin.setSpecialValueText("unlimited")
        limits_form.addRow("Module timeout", self.module_timeout_spin)
        limits_form.addRow("Max requests", self.budget_requests_spin)
        limits_form.addRow("Max wall clock", self.budget_wall_clock_spin)
        limits_form.addRow("Max LLM calls", self.budget_llm_spin)
        layout.addWidget(limits_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Runtime Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_scanner_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        auth_box = QGroupBox("Authenticated Testing")
        auth_form = QFormLayout(auth_box)
        auth_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.auth_bearer_input = QLineEdit()
        self.auth_bearer_input.setEchoMode(QLineEdit.Password)
        self.auth_bearer_input.setPlaceholderText("Bearer token applied to HTTP/browser probes")
        self.auth_cookie_input = QLineEdit()
        self.auth_cookie_input.setEchoMode(QLineEdit.Password)
        self.auth_cookie_input.setPlaceholderText("session=...; other=...")
        self.auth_headers_input = QPlainTextEdit()
        self.auth_headers_input.setPlaceholderText("One header per line, for example:\nAuthorization: Bearer ...\nX-API-Key: ...")
        self.auth_headers_input.setMaximumHeight(110)
        self.auth_probe_backoff_spin = QSpinBox()
        self.auth_probe_backoff_spin.setRange(0, 3600)
        auth_form.addRow("Bearer token", self.auth_bearer_input)
        auth_form.addRow("Cookie header", self.auth_cookie_input)
        auth_form.addRow("Headers", self.auth_headers_input)
        auth_form.addRow("Auth probe backoff", self.auth_probe_backoff_spin)
        layout.addWidget(auth_box)

        identities_box = QGroupBox("Test Identities (auth.identities)")
        identities_layout = QVBoxLayout(identities_box)
        self.identities_table = QTableWidget(0, 6)
        self.identities_table.setHorizontalHeaderLabels(
            ["Name", "Bearer token", "Cookies", "Verify URL", "Success marker", "Role"]
        )
        identities_header = self.identities_table.horizontalHeader()
        identities_header.setSectionResizeMode(1, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(2, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(3, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        identities_header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        identities_header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.identities_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.identities_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.identities_table.setMaximumHeight(180)
        identities_layout.addWidget(self.identities_table)
        identity_buttons = QHBoxLayout()
        add_identity_button = QPushButton("Add Identity")
        add_identity_button.clicked.connect(self._add_identity_row)
        remove_identity_button = QPushButton("Remove Selected")
        remove_identity_button.clicked.connect(self._remove_identity_rows)
        identity_buttons.addStretch(1)
        identity_buttons.addWidget(add_identity_button)
        identity_buttons.addWidget(remove_identity_button)
        identities_layout.addLayout(identity_buttons)
        identities_hint = QLabel(
            "Two verified identities are what idor_differ needs for horizontal "
            "comparison. Extra fields (headers, login, owner_id) are preserved; "
            "edit those in Raw YAML."
        )
        identities_hint.setWordWrap(True)
        identities_hint.setObjectName("opsSecondary")
        identities_layout.addWidget(identities_hint)
        layout.addWidget(identities_box)

        xss_box = QGroupBox("XSS Detection")
        xss_form = QFormLayout(xss_box)
        self.xss_browser_confirm_check = QCheckBox("Confirm execution with Playwright/Chromium")
        self.xss_max_points_spin = QSpinBox()
        self.xss_max_points_spin.setRange(1, 5000)
        self.xss_dalfox_timeout_spin = QSpinBox()
        self.xss_dalfox_timeout_spin.setRange(30, 7200)
        self.xss_dalfox_blind_oob_check = QCheckBox("Dalfox runs its own OOB session (stays FIRM)")
        self.xss_dalfox_blind_oob_check.setToolTip(
            "Uses dalfox --blind-oob on the public mesh instead of the "
            "framework-owned callback. No pollable session, so findings "
            "cannot reach CONFIRMED."
        )
        self.xss_dalfox_rate_spin = QSpinBox()
        self.xss_dalfox_rate_spin.setRange(0, 100000)
        self.xss_dalfox_rate_spin.setSpecialValueText("unlimited")
        self.xss_dalfox_rate_spin.setToolTip(
            "Global outbound cap for dalfox in requests/second."
        )
        xss_form.addRow("", self.xss_browser_confirm_check)
        xss_form.addRow("Max injection points", self.xss_max_points_spin)
        xss_form.addRow("Dalfox timeout", self.xss_dalfox_timeout_spin)
        xss_form.addRow("", self.xss_dalfox_blind_oob_check)
        xss_form.addRow("Dalfox rate limit", self.xss_dalfox_rate_spin)
        layout.addWidget(xss_box)

        nuclei_box = QGroupBox("Nuclei")
        nuclei_form = QFormLayout(nuclei_box)
        self.nuclei_full_cve_check = QCheckBox("Run full CVE pass only on confirmed apex")
        nuclei_form.addRow("", self.nuclei_full_cve_check)
        layout.addWidget(nuclei_box)

        sqli_box = QGroupBox("Blind SQLi (OAST)")
        sqli_form = QFormLayout(sqli_box)
        self.sqli_oast_check = QCheckBox("Hand sqlmap an OOB server for blind proof")
        self.sqli_oast_check.setToolTip(
            "Promotes only the exact URL that produced a callback. "
            "Needs oob server_url (wrapper mode) — a callback domain alone is not enough."
        )
        sqli_form.addRow("", self.sqli_oast_check)
        layout.addWidget(sqli_box)

        kr_box = QGroupBox("API Discovery (kiterunner)")
        kr_form = QFormLayout(kr_box)
        kr_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.kr_enabled_check = QCheckBox("Brute-force API routes (assetnote wordlists)")
        self.kr_enabled_check.setChecked(True)
        self.kr_wordlist_input = QLineEdit()
        self.kr_wordlist_input.setPlaceholderText("apiroutes-260227")
        self.kr_wordlist_input.setToolTip(
            "Remote list name; see `kr wordlist list` for current names."
        )
        self.kr_max_routes_spin = QSpinBox()
        self.kr_max_routes_spin.setRange(1, 20000)
        self.kr_max_routes_spin.setValue(1500)
        self.kr_max_routes_spin.setToolTip("Routes tried per target.")
        self.kr_max_targets_spin = QSpinBox()
        self.kr_max_targets_spin.setRange(1, 10)
        self.kr_max_targets_spin.setValue(2)
        self.kr_max_targets_spin.setToolTip(
            "Base URL plus api_endpoint origins, capped."
        )
        kr_form.addRow("", self.kr_enabled_check)
        kr_form.addRow("Wordlist", self.kr_wordlist_input)
        kr_form.addRow("Max routes", self.kr_max_routes_spin)
        kr_form.addRow("Max targets", self.kr_max_targets_spin)
        layout.addWidget(kr_box)

        semgrep_box = QGroupBox("Semgrep SAST")
        semgrep_form = QFormLayout(semgrep_box)
        semgrep_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.semgrep_enabled_check = QCheckBox("Scan JS bundles (repo-local rules)")
        self.semgrep_enabled_check.setChecked(True)
        self.semgrep_enabled_check.setToolTip(
            "Static only: taint flows file as MEDIUM/TENTATIVE, "
            "sinks as LOW. Never execution proof."
        )
        self.semgrep_rules_input = QLineEdit()
        self.semgrep_rules_input.setPlaceholderText("rules/semgrep")
        semgrep_form.addRow("", self.semgrep_enabled_check)
        semgrep_form.addRow("Rules", self.semgrep_rules_input)
        layout.addWidget(semgrep_box)

        ssrf_box = QGroupBox("SSRF Scan")
        ssrf_form = QFormLayout(ssrf_box)
        ssrf_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.ssrf_enabled_check = QCheckBox("Probe URL parameters (OOB-graded)")
        self.ssrf_enabled_check.setChecked(True)
        self.ssrf_enabled_check.setToolTip(
            "HTTP callback files HIGH/CONFIRMED, DNS-only MEDIUM/FIRM. "
            "Without an OOB channel nothing is probed."
        )
        self.ssrf_max_points_spin = QSpinBox()
        self.ssrf_max_points_spin.setRange(1, 30)
        self.ssrf_max_points_spin.setValue(6)
        self.ssrf_max_points_spin.setToolTip("URL parameters probed per run.")
        ssrf_form.addRow("", self.ssrf_enabled_check)
        ssrf_form.addRow("Max points", self.ssrf_max_points_spin)
        layout.addWidget(ssrf_box)

        crawl_box = QGroupBox("Browser Crawl")
        crawl_form = QFormLayout(crawl_box)
        crawl_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.crawl_enabled_check = QCheckBox("Render pages (one context per identity)")
        self.crawl_enabled_check.setChecked(True)
        self.crawl_enabled_check.setToolTip(
            "Verified identities render authenticated; anonymous always runs."
        )
        self.crawl_max_pages_spin = QSpinBox()
        self.crawl_max_pages_spin.setRange(1, 50)
        self.crawl_max_pages_spin.setValue(8)
        self.crawl_max_pages_spin.setToolTip("Pages rendered per context.")
        self.crawl_depth_spin = QSpinBox()
        self.crawl_depth_spin.setRange(0, 3)
        self.crawl_depth_spin.setValue(1)
        self.crawl_depth_spin.setToolTip("Same-origin link-following depth.")
        self.crawl_max_identities_spin = QSpinBox()
        self.crawl_max_identities_spin.setRange(0, 5)
        self.crawl_max_identities_spin.setValue(2)
        crawl_form.addRow("", self.crawl_enabled_check)
        crawl_form.addRow("Max pages", self.crawl_max_pages_spin)
        crawl_form.addRow("Depth", self.crawl_depth_spin)
        crawl_form.addRow("Max identities", self.crawl_max_identities_spin)
        layout.addWidget(crawl_box)

        logic_box = QGroupBox("Business Logic")
        logic_form = QFormLayout(logic_box)
        logic_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.logic_enabled_check = QCheckBox("Probe own-account cart logic")
        self.logic_enabled_check.setChecked(True)
        self.logic_enabled_check.setToolTip(
            "Differential proof only; every probe restored. "
            "Needs a verified identity."
        )
        self.logic_max_probes_spin = QSpinBox()
        self.logic_max_probes_spin.setRange(1, 40)
        self.logic_max_probes_spin.setValue(12)
        logic_form.addRow("", self.logic_enabled_check)
        logic_form.addRow("Max probes", self.logic_max_probes_spin)
        layout.addWidget(logic_box)

        fast_scan_box = QGroupBox("Fast Exposure Scan")
        fast_scan_form = QFormLayout(fast_scan_box)
        fast_scan_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.fast_scan_paths_input = QPlainTextEdit()
        self.fast_scan_paths_input.setPlaceholderText("High-signal paths, one per line")
        self.fast_scan_paths_input.setMaximumHeight(120)
        self.fast_scan_timeout_spin = QSpinBox()
        self.fast_scan_timeout_spin.setRange(1, 30)
        self.fast_scan_concurrency_spin = QSpinBox()
        self.fast_scan_concurrency_spin.setRange(1, 50)
        self.fast_scan_max_paths_spin = QSpinBox()
        self.fast_scan_max_paths_spin.setRange(1, 500)
        fast_scan_form.addRow("Paths", self.fast_scan_paths_input)
        fast_scan_form.addRow("Timeout", self.fast_scan_timeout_spin)
        fast_scan_form.addRow("Concurrency", self.fast_scan_concurrency_spin)
        fast_scan_form.addRow("Max paths", self.fast_scan_max_paths_spin)
        layout.addWidget(fast_scan_box)

        oob_box = QGroupBox("OOB Callback Infrastructure")
        oob_form = QFormLayout(oob_box)
        oob_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.oob_mode_combo = QComboBox()
        self.oob_mode_combo.addItem("Disabled", "")
        self.oob_mode_combo.addItem("public (free interactsh, own assets only)", "public")
        self.oob_mode_combo.addItem("wrapper (self-hosted shim)", "wrapper")
        self.oob_mode_combo.setToolTip(
            "public: multiplexed session, needs only the interactsh-client "
            "binary (baked into the docker image). wrapper: your own "
            "interactsh-compatible HTTP shim, needs a domain + wildcard DNS."
        )
        self.oob_enabled_check = QCheckBox("Enable OOB checks")
        self.oob_enabled_check.setChecked(True)
        self.oob_enabled_check.setToolTip(
            "Off turns OOB off everywhere without deleting the settings."
        )
        self.oob_callback_domain_input = QLineEdit()
        self.oob_callback_domain_input.setPlaceholderText("oob.example.com")
        self.oob_server_url_input = QLineEdit()
        self.oob_server_url_input.setPlaceholderText("https://interactsh-wrapper.example")
        self.oob_poll_url_input = QLineEdit()
        self.oob_poll_url_input.setPlaceholderText("https://interactsh-wrapper.example/interactions")
        self.oob_token_input = QLineEdit()
        self.oob_token_input.setEchoMode(QLineEdit.Password)
        self.oob_poll_interval_spin = QSpinBox()
        self.oob_poll_interval_spin.setRange(1, 300)
        self.oob_poll_timeout_spin = QSpinBox()
        self.oob_poll_timeout_spin.setRange(1, 3600)
        oob_form.addRow("Mode", self.oob_mode_combo)
        oob_form.addRow("", self.oob_enabled_check)
        oob_form.addRow("Callback domain", self.oob_callback_domain_input)
        oob_form.addRow("Server URL", self.oob_server_url_input)
        oob_form.addRow("Poll URL", self.oob_poll_url_input)
        oob_form.addRow("Token", self.oob_token_input)
        oob_form.addRow("Poll interval", self.oob_poll_interval_spin)
        oob_form.addRow("Poll timeout", self.oob_poll_timeout_spin)
        layout.addWidget(oob_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Scanner Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_actions_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        actions_box = QGroupBox("Registered Actions")
        actions_layout = QVBoxLayout(actions_box)
        self.actions_table = QTableWidget(0, 5)
        self.actions_table.setHorizontalHeaderLabels(
            ["Action", "Risk", "Detectability", "Requires", "Description"]
        )
        actions_header = self.actions_table.horizontalHeader()
        actions_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.actions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        actions_layout.addWidget(self.actions_table)
        layout.addWidget(actions_box, 1)

        hint = QLabel(
            "The risk ceiling (--max-risk / Engagement → Risk ceiling) admits "
            "actions at or below the selected level; SAFE and LOW admit nothing "
            "that sends an injection payload."
        )
        hint.setWordWrap(True)
        hint.setObjectName("opsSecondary")
        layout.addWidget(hint)
        self._refresh_actions_table()
        return tab

    def _refresh_actions_table(self):
        if not hasattr(self, "actions_table"):
            return
        rank = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "DESTRUCTIVE": 4}
        colors = {
            "SAFE": "#4ade80", "LOW": "#93c5fd", "MEDIUM": "#fde047",
            "HIGH": "#fdba74", "DESTRUCTIVE": "#fb7185",
        }
        metas = sorted(
            ActionRegistry.list(),
            key=lambda meta: (rank.get(meta.risk.value, 9), meta.id),
        )
        self.actions_table.setRowCount(len(metas))
        for row, meta in enumerate(metas):
            values = [
                meta.id,
                meta.risk.value,
                meta.detectability,
                ", ".join(meta.requires),
                meta.description,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    color = colors.get(meta.risk.value)
                    if color:
                        item.setForeground(QColor(color))
                self.actions_table.setItem(row, col, item)

    def _build_tools_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        tools_box = QGroupBox("External Tool Readiness")
        tools_layout = QVBoxLayout(tools_box)
        self.tools_backend_label = QLabel("Backend: local")
        self.tools_backend_label.setWordWrap(True)
        self.tools_backend_label.setObjectName("opsSecondary")
        tools_layout.addWidget(self.tools_backend_label)
        self.tools_table = QTableWidget(0, 5)
        self.tools_table.setHorizontalHeaderLabels(
            ["Tool", "Ready", "Runs via", "Categories", "Purpose"]
        )
        self.tools_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        tools_layout.addWidget(self.tools_table)
        tool_buttons = QHBoxLayout()
        self.refresh_tools_button = QPushButton("Refresh Tools")
        self.refresh_tools_button.clicked.connect(self._refresh_tools_status)
        self.open_tools_requirements_button = QPushButton("Open Requirements")
        self.open_tools_requirements_button.clicked.connect(self.open_tools_requirements)
        self.install_tools_button = QPushButton("Install Missing")
        self.install_tools_button.clicked.connect(self.install_missing_tools)
        tool_buttons.addStretch(1)
        tool_buttons.addWidget(self.refresh_tools_button)
        tool_buttons.addWidget(self.install_tools_button)
        tool_buttons.addWidget(self.open_tools_requirements_button)
        tools_layout.addLayout(tool_buttons)
        layout.addWidget(tools_box, 2)

        requirements_box = QGroupBox("tools_requirements.txt")
        requirements_layout = QVBoxLayout(requirements_box)
        self.tools_requirements_preview = QPlainTextEdit()
        self.tools_requirements_preview.setReadOnly(True)
        self.tools_requirements_preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.tools_requirements_preview.setFont(code_font(11))
        requirements_layout.addWidget(self.tools_requirements_preview)
        layout.addWidget(requirements_box, 1)
        return tab

    def _build_keys_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        readiness_box = QGroupBox("Access Readiness")
        readiness_layout = QVBoxLayout(readiness_box)
        self.keys_table = QTableWidget(0, 3)
        self.keys_table.setHorizontalHeaderLabels(["Service", "Ready", "Key"])
        self.keys_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.keys_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.keys_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.keys_table.setMinimumWidth(0)
        self.keys_table.setMaximumHeight(180)
        readiness_layout.addWidget(self.keys_table)
        self.refresh_keys_button = QPushButton("Refresh Keys")
        self.refresh_keys_button.clicked.connect(self._refresh_key_status)
        readiness_layout.addWidget(self.refresh_keys_button)
        layout.addWidget(readiness_box)

        key_box = QGroupBox("Service API Keys")
        key_layout = QGridLayout(key_box)
        key_layout.addWidget(QLabel("Service"), 0, 0)
        key_layout.addWidget(QLabel("Config value"), 0, 1)
        key_layout.addWidget(QLabel("Environment fallback"), 0, 2)
        self.api_key_inputs = {}
        for row, (service, spec) in enumerate(sorted(KEY_SPECS.items()), start=1):
            key_input = QLineEdit()
            key_input.setEchoMode(QLineEdit.Password)
            key_input.setPlaceholderText("leave blank to use env")
            self.api_key_inputs[service] = key_input
            env_label = QLabel(", ".join(spec.env))
            env_label.setWordWrap(True)
            key_layout.addWidget(QLabel(spec.label), row, 0)
            key_layout.addWidget(key_input, row, 1)
            key_layout.addWidget(env_label, row, 2)
        key_layout.setColumnStretch(1, 2)
        key_layout.setColumnStretch(2, 2)
        layout.addWidget(key_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save API Keys")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)
        return tab

    def _build_raw_config_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        self.raw_config_editor = QPlainTextEdit()
        self.raw_config_editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.raw_config_editor.setFont(code_font(12))
        layout.addWidget(self.raw_config_editor, 1)
        button_row = QHBoxLayout()
        validate_button = QPushButton("Apply Raw YAML")
        validate_button.clicked.connect(self._save_raw_config_editor)
        reload_button = QPushButton("Reload Raw")
        reload_button.clicked.connect(self._load_raw_config_editor)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(validate_button)
        layout.addLayout(button_row)
        return tab

    def _build_ops_strip(self) -> QFrame:
        """Live run context: target, mode, state pill, progress, exposure."""
        ops_strip = QFrame()
        ops_strip.setObjectName("opsStrip")
        ops_layout = QGridLayout(ops_strip)
        ops_layout.setContentsMargins(14, 10, 14, 10)
        self.operation_target_label = QLabel("Target: -")
        self.operation_target_label.setObjectName("opsPrimary")
        self.operation_target_label.setWordWrap(True)
        self.operation_target_label.setMinimumWidth(0)
        self.operation_mode_label = QLabel("Mode: -")
        self.operation_mode_label.setObjectName("opsSecondary")
        self.operation_mode_label.setWordWrap(True)
        self.operation_mode_label.setMinimumWidth(0)
        self.operation_state_label = QLabel("Ready")
        self.operation_state_label.setObjectName("opsState")
        self.operation_state_label.setProperty("state", "idle")
        self.operation_state_label.setMinimumWidth(0)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumWidth(0)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.exposure_label = QLabel("Exposure map: waiting for data")
        self.exposure_label.setObjectName("opsSecondary")
        self.exposure_label.setWordWrap(True)
        self.exposure_label.setMinimumWidth(0)
        ops_layout.addWidget(self.operation_target_label, 0, 0)
        ops_layout.addWidget(self.operation_mode_label, 1, 0)
        ops_layout.addWidget(self.operation_state_label, 0, 1, 2, 1)
        ops_layout.addWidget(self.progress_bar, 0, 2)
        ops_layout.addWidget(self.exposure_label, 1, 2)
        ops_layout.setColumnStretch(0, 2)
        ops_layout.setColumnStretch(2, 3)
        return ops_strip

    def _build_run_screen(self) -> QWidget:
        """Screen 0: mission setup + live log (was: side panel + ops strip + Log tab)."""
        page = QWidget()
        page.setObjectName("screenRun")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Right pane first: the control panel wires buttons to log_output.
        right = QWidget()
        right.setMinimumWidth(420)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right_layout.addWidget(self._build_ops_strip())

        log_caption = QLabel("Run log")
        log_caption.setObjectName("sectionCaption")
        right_layout.addWidget(log_caption)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_output.setFont(code_font(12))
        self.log_output.setPlaceholderText(
            "Output from orchestrator.py appears here once a run starts."
        )
        right_layout.addWidget(self.log_output, 1)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_controls())
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([380, 900])
        layout.addWidget(splitter, 1)
        return page

    def _build_triage_screen(self) -> QWidget:
        """Screen 1: findings filter bar, table and detail pane (was: Findings tab)."""
        findings_widget = QWidget()
        findings_widget.setObjectName("screenTriage")
        findings_layout = QVBoxLayout(findings_widget)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(6)
        self.finding_search = QLineEdit()
        self.finding_search.setPlaceholderText("Filter title, ID, category or description")
        self.finding_search.setMinimumWidth(0)
        self.finding_severity_combo = QComboBox()
        self.finding_severity_combo.addItems(
            ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        self.finding_confidence_combo = QComboBox()
        self.finding_confidence_combo.addItems(
            ["All confidence", "CONFIRMED", "FIRM", "TENTATIVE"]
        )
        self.finding_verified_combo = QComboBox()
        self.finding_verified_combo.addItems(
            ["All verification", "Verified only", "Unverified only"]
        )
        self.finding_triage_combo = QComboBox()
        self.finding_triage_combo.addItems([
            "All triage", "Untriaged only", "True positive", "False positive", "Out of scope",
        ])
        self.finding_count_label = QLabel("showing 0 of 0")
        self.finding_count_label.setObjectName("opsSecondary")
        self.finding_search.setClearButtonEnabled(True)
        self.finding_search.textChanged.connect(self._apply_finding_filter)
        self.finding_severity_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_confidence_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_verified_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_triage_combo.currentIndexChanged.connect(self._apply_finding_filter)
        reset_filters_button = QPushButton("Reset")
        reset_filters_button.setObjectName("btnGhost")
        reset_filters_button.clicked.connect(self._reset_finding_filters)
        filter_row.addWidget(self.finding_search, 1)
        filter_row.addWidget(self.finding_severity_combo)
        filter_row.addWidget(self.finding_confidence_combo)
        filter_row.addWidget(self.finding_verified_combo)
        filter_row.addWidget(self.finding_triage_combo)
        filter_row.addWidget(reset_filters_button)
        filter_row.addWidget(self.finding_count_label)
        findings_layout.addLayout(filter_row)

        self.findings_table = QTableWidget(0, 10)
        self.findings_table.setHorizontalHeaderLabels([
            "ID", "Priority", "Severity", "Score", "Confidence",
            "Title", "Category", "Module", "Verdict", "Assets",
        ])
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        # QTableWidget's built-in sorting only compares DisplayRole strings
        # ("100" < "10" < "2"), so the table sorts itself through
        # `_sort_findings` with real ranks instead.
        self.findings_table.setSortingEnabled(False)
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self._sort_findings)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.findings_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_table.customContextMenuRequested.connect(self._findings_context_menu)
        self.findings_table.itemSelectionChanged.connect(self._update_finding_detail)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setLineWrapMode(QTextEdit.NoWrap)
        self.finding_detail.setMinimumHeight(160)
        self.finding_detail.setPlaceholderText(
            "Select a finding to see its description, remediation and evidence."
        )

        # Verdict bar: the analyst's primary controls, not buried in a menu.
        detail_container = QWidget()
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)
        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(6)
        self.verdict_chip = QLabel("Untriaged")
        self.verdict_chip.setObjectName("verdictChip")
        self.verdict_chip.setProperty("verdict", "none")
        verdict_row.addWidget(self.verdict_chip)
        self.tp_button = QPushButton("True positive")
        self.tp_button.setObjectName("btnVerdict")
        self.tp_button.setToolTip("Mark selected finding(s) as true positive (t)")
        self.tp_button.clicked.connect(lambda: self._apply_verdict_action("true_positive"))
        self.fp_button = QPushButton("False positive")
        self.fp_button.setObjectName("btnVerdict")
        self.fp_button.setToolTip("Mark selected finding(s) as false positive (f)")
        self.fp_button.clicked.connect(lambda: self._apply_verdict_action("false_positive"))
        self.oos_button = QPushButton("Out of scope")
        self.oos_button.setObjectName("btnVerdict")
        self.oos_button.setToolTip("Mark selected finding(s) as out of scope (o)")
        self.oos_button.clicked.connect(lambda: self._apply_verdict_action("out_of_scope"))
        self.note_button = QPushButton("Note…")
        self.note_button.setObjectName("btnGhost")
        self.note_button.clicked.connect(self._edit_selected_note)
        self.open_evidence_button = QPushButton("Open evidence")
        self.open_evidence_button.setObjectName("btnGhost")
        self.open_evidence_button.clicked.connect(self._open_selected_evidence)
        self.filter_module_button = QPushButton("Filter by module")
        self.filter_module_button.setObjectName("btnGhost")
        self.filter_module_button.clicked.connect(self._filter_by_selected_module)
        verdict_row.addWidget(self.tp_button)
        verdict_row.addWidget(self.fp_button)
        verdict_row.addWidget(self.oos_button)
        verdict_row.addSpacing(8)
        verdict_row.addWidget(self.note_button)
        verdict_row.addWidget(self.open_evidence_button)
        verdict_row.addWidget(self.filter_module_button)
        verdict_row.addStretch(1)
        detail_layout.addLayout(verdict_row)
        detail_layout.addWidget(self.finding_detail, 1)

        finding_splitter = QSplitter(Qt.Vertical)
        finding_splitter.addWidget(self.findings_table)
        finding_splitter.addWidget(detail_container)
        finding_splitter.setStretchFactor(0, 3)
        finding_splitter.setStretchFactor(1, 2)
        findings_layout.addWidget(finding_splitter, 1)

        # Keyboard: focus filter, triage letters when the table has focus.
        find_shortcut = QShortcut(QKeySequence.Find, findings_widget)
        find_shortcut.activated.connect(self.focus_finding_filter)
        self.findings_table.installEventFilter(self)
        return findings_widget

    def eventFilter(self, obj, event):
        if obj is getattr(self, "findings_table", None) and event.type() == QEvent.KeyPress:
            key = event.key()
            mapping = {
                Qt.Key_T: "true_positive",
                Qt.Key_F: "false_positive",
                Qt.Key_O: "out_of_scope",
            }
            if key in mapping and event.modifiers() in (Qt.NoModifier, Qt.ShiftModifier):
                self._apply_verdict_action(mapping[key])
                return True
        return super().eventFilter(obj, event)

    def focus_finding_filter(self):
        self.show_screen(1)
        self.finding_search.setFocus()
        self.finding_search.selectAll()

    def _reset_finding_filters(self):
        self.finding_search.clear()
        self.finding_severity_combo.setCurrentIndex(0)
        self.finding_confidence_combo.setCurrentIndex(0)
        self.finding_verified_combo.setCurrentIndex(0)
        self.finding_triage_combo.setCurrentIndex(0)

    def _selected_findings(self) -> list[dict]:
        """Every selected row, not just the current one — a 10-row selection
        must not silently apply a verdict to a single finding."""
        rows = sorted({index.row() for index in self.findings_table.selectedIndexes()})
        by_id = {str(f.get("id", "")): f for f in self.current_findings}
        picked = []
        for row in rows:
            item = self.findings_table.item(row, 0)
            if item:
                finding = by_id.get(item.text())
                if finding is not None:
                    picked.append(finding)
        return picked

    def _apply_verdict_action(self, verdict: str):
        findings = self._selected_findings()
        if not findings:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        for finding in findings:
            self._set_finding_verdict(finding, verdict, refilter=False)
        self._apply_finding_filter()
        label = VERDICT_LABELS.get(verdict, verdict) or "Untriaged"
        if len(findings) == 1:
            self.statusBar().showMessage(f"{findings[0].get('id')} → {label}", 4000)
        else:
            self.statusBar().showMessage(
                f"{len(findings)} findings → {label}", 4000
            )

    def _edit_selected_note(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        self._edit_triage_note(finding)

    def _open_selected_evidence(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        self._open_finding_evidence(finding)

    def _filter_by_selected_module(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        module_id = str(finding.get("module_id", ""))
        if module_id:
            self.finding_search.setText(module_id)

    def _build_graph_screen(self) -> QWidget:
        """Screen 2: asset graph + attack graph side by side in sub-tabs."""
        page = QWidget()
        page.setObjectName("screenGraph")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setDrawBase(False)

        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_header = QGridLayout()
        self.graph_summary = QLabel("No graph loaded")
        self.graph_summary.setWordWrap(True)
        self.graph_summary.setMinimumWidth(0)
        self.graph_aggregate_check = QCheckBox("Group dense types")
        self.graph_aggregate_check.setChecked(True)
        self.graph_aggregate_check.stateChanged.connect(self.refresh_graph)
        self.graph_labels_check = QCheckBox("Labels")
        self.graph_labels_check.setChecked(False)
        self.graph_labels_check.stateChanged.connect(self.refresh_graph)
        self.graph_edges_check = QCheckBox("Relations")
        self.graph_edges_check.setChecked(True)
        self.graph_edges_check.stateChanged.connect(self.refresh_graph)
        self.fit_graph_button = QPushButton("Fit")
        self.fit_graph_button.clicked.connect(self.refresh_graph)
        graph_header.addWidget(self.graph_summary, 0, 0, 1, 4)
        graph_header.addWidget(self.graph_aggregate_check, 1, 0)
        graph_header.addWidget(self.graph_labels_check, 1, 1)
        graph_header.addWidget(self.graph_edges_check, 1, 2)
        graph_header.addWidget(self.fit_graph_button, 1, 3)
        graph_header.setColumnStretch(0, 1)
        graph_layout.addLayout(graph_header)
        self.graph_view = QWebEngineView()
        # Default page background is white — a jarring flash before the
        # dark graph html paints (and a white block in headless runs).
        self.graph_view.page().setBackgroundColor(QColor("#090d13"))
        self.graph_view.setMinimumSize(0, 0)
        graph_layout.addWidget(self.graph_view, 1)
        tabs.addTab(graph_widget, "Asset Graph")

        attack_widget = QWidget()
        attack_layout = QVBoxLayout(attack_widget)
        attack_layout.setContentsMargins(0, 0, 0, 0)
        attack_layout.setSpacing(6)
        self.attack_graph_summary = QLabel("No attack graph loaded")
        self.attack_graph_summary.setWordWrap(True)
        self.attack_graph_summary.setObjectName("opsPrimary")
        attack_layout.addWidget(self.attack_graph_summary)

        probe_caption = QLabel("Probe plan")
        probe_caption.setObjectName("subtitle")
        attack_layout.addWidget(probe_caption)
        self.probe_plan_label = QLabel("Probe plan: not recorded")
        self.probe_plan_label.setWordWrap(True)
        self.probe_plan_label.setObjectName("opsSecondary")
        attack_layout.addWidget(self.probe_plan_label)
        self.probe_plan_table = QTableWidget(0, 2)
        self.probe_plan_table.setHorizontalHeaderLabels(["Reason not proposed", "Surfaces"])
        self.probe_plan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.probe_plan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.probe_plan_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.probe_plan_table.setMaximumHeight(120)
        attack_layout.addWidget(self.probe_plan_table)

        self.attack_graph_view = QWebEngineView()
        self.attack_graph_view.page().setBackgroundColor(QColor("#090d13"))
        self.attack_graph_view.setMinimumSize(0, 0)
        attack_layout.addWidget(self.attack_graph_view, 1)
        tabs.addTab(attack_widget, "Attack Graph")

        layout.addWidget(tabs, 1)
        return page

    def _build_data_screen(self) -> QWidget:
        """Screen 3: assets, modules, evidence, submissions in sub-tabs."""
        page = QWidget()
        page.setObjectName("screenData")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setDrawBase(False)
        self._table_filters: dict[QTableWidget, tuple[QLineEdit, QLabel, QComboBox | None]] = {}

        self.assets_table = QTableWidget(0, 4)
        self.assets_table.setHorizontalHeaderLabels(["Type", "Value", "Confidence", "Sources"])
        self.assets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        tabs.addTab(self._wrap_data_tab(self.assets_table, "Filter assets…"), "Assets")

        self.modules_table = QTableWidget(0, 8)
        self.modules_table.setHorizontalHeaderLabels([
            "Stage", "Module", "Status", "Detectability", "Requests", "Assets +", "Findings +", "Error",
        ])
        self.modules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.modules_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.modules_table.setSortingEnabled(True)
        status_combo = QComboBox()
        status_combo.setObjectName("filterCombo")
        status_combo.addItem("All statuses")
        for status in (
            "completed", "running", "pending", "timeout", "incomplete",
            "error", "failed", "blocked", "skipped",
        ):
            status_combo.addItem(status)
        status_combo.setToolTip("Show only modules with this status")
        tabs.addTab(
            self._wrap_data_tab(self.modules_table, "Filter modules…", status_combo),
            "Modules",
        )

        self.evidence_table = QTableWidget(0, 5)
        self.evidence_table.setHorizontalHeaderLabels(["ID", "Module", "Type", "Subject", "Path"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.evidence_table.cellDoubleClicked.connect(self._open_evidence_cell)
        tabs.addTab(self._wrap_data_tab(self.evidence_table, "Filter evidence…"), "Evidence")

        self.submissions_table = QTableWidget(0, 3)
        self.submissions_table.setHorizontalHeaderLabels(["File", "Size", "Path"])
        self.submissions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.submissions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.submissions_table.cellDoubleClicked.connect(self._open_submission_cell)
        tabs.addTab(
            self._wrap_data_tab(self.submissions_table, "Filter submissions…"),
            "Submissions",
        )

        layout.addWidget(tabs, 1)
        return page

    def _wrap_data_tab(
        self, table: QTableWidget, placeholder: str, status_combo: QComboBox | None = None
    ) -> QWidget:
        """Filter bar + table, with search, status combo, and live counts."""
        page = QWidget()
        bar_layout = QHBoxLayout()
        bar_layout.setContentsMargins(0, 0, 0, 0)
        bar_layout.setSpacing(6)
        search = QLineEdit()
        search.setPlaceholderText(placeholder)
        search.setClearButtonEnabled(True)
        count_label = QLabel("0 of 0")
        count_label.setObjectName("opsSecondary")
        bar_layout.addWidget(search, 1)
        if status_combo is not None:
            bar_layout.addWidget(status_combo)
        bar_layout.addWidget(count_label)
        table_layout = QVBoxLayout(page)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(4)
        table_layout.addLayout(bar_layout)
        table_layout.addWidget(table, 1)

        self._table_filters[table] = (search, count_label, status_combo)
        search.textChanged.connect(lambda _text, t=table: self._apply_table_filter(t))
        if status_combo is not None:
            status_combo.currentIndexChanged.connect(
                lambda _index, t=table: self._apply_table_filter(t)
            )
        # Sorting moves rows under a live filter; re-apply so hidden rows
        # stay hidden in the new order.
        table.horizontalHeader().sortIndicatorChanged.connect(
            lambda _order, _sec, t=table: self._apply_table_filter(t)
        )
        table.setSortingEnabled(True)
        table.horizontalHeader().setSortIndicatorShown(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda pos, t=table: self._table_context_menu(t, pos)
        )
        return page

    def _apply_table_filter(self, table: QTableWidget):
        entry = getattr(self, "_table_filters", {}).get(table)
        if not entry:
            return
        search, count_label, status_combo = entry
        query = search.text().strip().lower()
        status = ""
        if status_combo is not None and status_combo.currentIndex() > 0:
            status = status_combo.currentText().strip().lower()
        total = table.rowCount()
        visible = 0
        for row in range(total):
            matches_query = not query
            if query:
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    if item and query in item.text().lower():
                        matches_query = True
                        break
            matches_status = True
            if status:
                item = table.item(row, 2)
                matches_status = item is not None and item.text().strip().lower() == status
            show = matches_query and matches_status
            table.setRowHidden(row, not show)
            if show:
                visible += 1
        count_label.setText(f"{visible} of {total}")

    def _table_context_menu(self, table: QTableWidget, pos):
        index = table.indexAt(pos)
        menu = QMenu(self)
        copy_cell_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy row")
        copy_tsv_action = menu.addAction("Copy selected rows (TSV)")
        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        clipboard = QApplication.clipboard()
        if chosen is copy_cell_action:
            item = table.item(index.row(), index.column()) if index.isValid() else None
            if item:
                clipboard.setText(item.text())
                self.statusBar().showMessage("Cell copied", 2000)
        elif chosen is copy_row_action:
            row = index.row()
            texts = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                texts.append(item.text() if item else "")
            clipboard.setText("\t".join(texts))
            self.statusBar().showMessage(f"Row {row + 1} copied", 2000)
        elif chosen is copy_tsv_action:
            rows = sorted({i.row() for i in table.selectedIndexes()})
            lines = []
            for row in rows:
                texts = []
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    texts.append(item.text() if item else "")
                lines.append("\t".join(texts))
            clipboard.setText("\n".join(lines))
            self.statusBar().showMessage(f"{len(lines)} row(s) copied", 2000)

    def _build_report_screen(self) -> QWidget:
        """Screen 4: report preview, markdown, attack plan, summary JSON."""
        page = QWidget()
        page.setObjectName("screenReport")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        path_row = QHBoxLayout()
        path_row.setSpacing(16)
        self.report_path_label = QLabel("No report loaded")
        self.report_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_path_label.setWordWrap(True)
        self.report_path_label.setMinimumWidth(0)
        self.attack_plan_path_label = QLabel("No attack plan loaded")
        self.attack_plan_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.attack_plan_path_label.setWordWrap(True)
        self.attack_plan_path_label.setMinimumWidth(0)
        path_row.addWidget(self.report_path_label, 1)
        path_row.addWidget(self.attack_plan_path_label, 1)
        layout.addLayout(path_row)

        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setElideMode(Qt.ElideRight)
        tabs.tabBar().setDrawBase(False)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_raw = QPlainTextEdit()
        self.report_raw.setReadOnly(True)
        self.report_raw.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.report_raw.setFont(code_font(12))
        self.attack_plan_preview = QTextEdit()
        self.attack_plan_preview.setReadOnly(True)
        self.summary_json = QPlainTextEdit()
        self.summary_json.setReadOnly(True)
        self.summary_json.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.summary_json.setFont(code_font(12))
        tabs.addTab(self.report_preview, "Rendered")
        tabs.addTab(self.report_raw, "Markdown")
        tabs.addTab(self.attack_plan_preview, "Attack Plan")
        tabs.addTab(self.summary_json, "Summary JSON")
        layout.addWidget(tabs, 1)
        return page

    def _metric_card(self, label: str, value_label: QLabel, tone: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        card.setProperty("tone", tone)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        label_widget = QLabel(label.upper())
        label_widget.setObjectName("metricLabel")
        value_label.setObjectName("metricValue")
        layout.addWidget(label_widget)
        layout.addWidget(value_label)
        return card

    def _refresh_module_list(self):
        selected = self.module_combo.currentData() if hasattr(self, "module_combo") else None
        self.module_combo.clear()
        stage_filter = self.stage_filter_combo.currentData() if hasattr(self, "stage_filter_combo") else 0
        for module_id in get_all_module_ids():
            entry = MODULE_REGISTRY[module_id]
            if stage_filter and entry.get("stage") != stage_filter:
                continue
            kind = " [ACTIVE]" if entry.get("active") else ""
            label = f"S{entry['stage']}  {module_id}{kind}"
            self.module_combo.addItem(label, module_id)
            if selected == module_id:
                self.module_combo.setCurrentIndex(self.module_combo.count() - 1)
        self._sync_mode()
        self._update_module_hint()

    def _sync_mode(self):
        self.module_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        self.stage_filter_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        if hasattr(self, "ai_run_button"):
            self.ai_run_button.setEnabled(self.mode_combo.currentText() != "Single module")

    def _update_module_hint(self):
        module_id = self.module_combo.currentData()
        entry = MODULE_REGISTRY.get(module_id or "", {})
        if not entry:
            self.module_hint.setText("-")
            return
        kind = "active" if entry.get("active") else "passive"
        deps = ", ".join(entry.get("depends_on", [])) or "none"
        self.module_hint.setText(
            f"Stage {entry.get('stage')} · {entry.get('detectability')} · {kind} · deps: {deps}"
        )

    def _llm_status(self) -> tuple[bool, str]:
        llm = get_llm_config(self._read_config())
        model = llm.get("model", "")
        local_prefixes = ("ollama/", "lm_studio/", "hosted_vllm/")
        needs_key = bool(model) and not model.startswith(local_prefixes)
        ready = bool(model) and (bool(llm.get("api_key")) or not needs_key)
        if ready:
            return True, f"LLM ready: {model}"
        return False, f"LLM key missing for {model or 'configured model'}"

    def _prefer_llm_if_ready(self):
        ready, _message = self._llm_status()
        if ready and hasattr(self, "mode_combo"):
            index = self.mode_combo.findText("LLM")
            if index >= 0:
                self.mode_combo.setCurrentIndex(index)

    def start_llm_scan(self):
        index = self.mode_combo.findText("LLM")
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
        self.start_scan()

    def choose_output_dir(self):
        selected = QFileDialog.getExistingDirectory(
            self,
            "Output Directory",
            str(self.output_dir),
        )
        if selected:
            self.output_dir = Path(selected)
            self.output_input.setText(str(self.output_dir))
            self._update_operation_context()

    def choose_config_file(self):
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Config File",
            str(self.config_path.parent),
            "YAML (*.yaml *.yml);;All files (*)",
        )
        if not selected:
            return
        self.config_path = Path(selected)
        self._load_settings_form()
        self._update_operation_context()
        self.status_label.setText(f"Config: {self.config_path.name}")

    def _confirm_engagement(self) -> bool:
        """Gate chain execution at MEDIUM and above behind an explicit yes."""
        if not (self.pentest_check.isChecked() and self.execute_check.isChecked()):
            return True
        risk = self.risk_combo.currentText()
        if risk in ("SAFE", "LOW"):
            return True
        answer = QMessageBox.warning(
            self,
            "Authorisation Required",
            f"Target: {self.target_input.text().strip()}\n"
            f"Risk ceiling: {risk}\n"
            f"Max actions: {self.max_actions_spin.value()} | "
            f"Max chains: {self.max_chains_spin.value()}\n\n"
            "This will execute attack actions against the target.\n"
            "Only continue if you are authorised to test it.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return answer == QMessageBox.Yes

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        if not self._confirm_engagement():
            return

        mode = self.mode_combo.currentText()
        module = self.module_combo.currentData() if mode == "Single module" else None
        args = build_scan_args(
            target=target,
            output_dir=self.output_dir,
            config_path=self.config_path,
            mode=mode,
            active=self.active_check.isChecked(),
            module=module,
            pentest=self.pentest_check.isChecked(),
            execute=self.execute_check.isChecked(),
            max_risk=self.risk_combo.currentText(),
            max_actions=self.max_actions_spin.value(),
            max_chains=self.max_chains_spin.value(),
        )

        self.report_after_process = (
            self.auto_report_check.isChecked()
            and mode in ("Single module", "LLM")
            and self.module_combo.currentData() != "reporting"
        )
        self.running_report = False
        self._start_process(args)

    def generate_report(self):
        self.run_module_action("reporting", report_run=True)

    def prioritize_findings(self):
        self.run_module_action("risk_prioritization")

    def generate_submissions(self):
        self.run_module_action("bounty_submission")

    def generate_attack_plan(self):
        self.run_module_action("attack_planner")

    def run_module_action(self, module_id: str, report_run: bool = False):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        args = build_scan_args(
            target=target,
            output_dir=self.output_dir,
            config_path=self.config_path,
            module=module_id,
        )
        self._start_process(args, report_run=report_run)

    def open_report(self):
        path = self._report_path()
        if not path.exists():
            QMessageBox.information(self, "Report Missing", "No report exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def open_target_folder(self):
        path = self.output_dir / self._target_output_name()
        if not path.exists():
            QMessageBox.information(self, "Folder Missing", "No output folder exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _set_status(self, state: str, text: str, ops_text: str | None = None):
        """Drive the header pill and ops-strip badge from one state value.

        `state` is one of idle / busy / ok / error; theme.qss styles each via
        `[state="..."]` so a failure can never look like a success.
        """
        self.status_label.setText(text)
        self.status_label.setProperty("state", state)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        if hasattr(self, "operation_state_label"):
            self.operation_state_label.setText(ops_text or text)
            self.operation_state_label.setProperty("state", state)
            self.operation_state_label.style().unpolish(self.operation_state_label)
            self.operation_state_label.style().polish(self.operation_state_label)

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        total = int(max(0, seconds))
        return f"{total // 60:02d}:{total % 60:02d}"

    def _stop_run_timers(self):
        self._elapsed_timer.stop()
        self._poll_timer.stop()
        self._run_started_at = None

    def _tick_run_progress(self):
        if self._run_started_at is None:
            return
        elapsed = self._format_elapsed(time.monotonic() - self._run_started_at)
        total = max(len(get_all_module_ids()), 1)
        completed = len((self.current_module or {}).get("completed", []))
        self.status_label.setText(f"Running · {completed}/{total} · {elapsed}")

    def _poll_run_state(self):
        """Tail state/module.json so metrics move while the engine runs.

        The orchestrator persists state at least five times per run, so a
        750ms poll shows module completions almost immediately instead of
        freezing the progress bar at its pre-run value.
        """
        target_dir = self.output_dir / self._target_output_name()
        module = self._read_json(target_dir / "state" / "module.json", {})
        if isinstance(module, dict) and module:
            self.current_module = module
            stats = module.get("stats", {})
            completed = len(module.get("completed", []))
            total = max(len(get_all_module_ids()), 1)
            self.progress_bar.setValue(min(100, int((completed / total) * 100)))
            suffix = f", {self._incomplete_count(module)} incomplete" \
                if self._incomplete_count(module) else ""
            self.progress_bar.setFormat(f"{completed}/{total} modules complete{suffix}")
            self.completed_value.setText(str(completed))
            self.skipped_value.setText(str(len(module.get("skipped", []))))
            self.blocked_value.setText(str(len(module.get("blocked", []))))
            self.incomplete_value.setText(str(self._incomplete_count(module)))
            self.requests_value.setText(str(stats.get("total_requests", "-")))
        self._tick_run_progress()

    def _restore_run_buttons(self):
        self.run_button.setEnabled(True)
        self.ai_run_button.setEnabled(True)
        self.ai_plan_button.setEnabled(True)
        self.generate_report_button.setEnabled(True)
        self.prioritize_button.setEnabled(True)
        self.submission_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def _start_process(self, args: list[str], report_run: bool = False):
        self.running_report = report_run
        stamp = time.strftime("%H:%M:%S")
        self.log_output.appendPlainText(
            f"\n── run {stamp} {'(report)' if report_run else ''} ──\n"
            f"$ {sys.executable} {' '.join(args)}\n"
        )
        ops_text = "Report generation" if report_run else "Operation active"
        pill_text = "Generating report" if report_run else "Running"
        self._set_status("busy", pill_text, ops_text)
        self.run_button.setEnabled(False)
        self.ai_run_button.setEnabled(False)
        self.ai_plan_button.setEnabled(False)
        self.generate_report_button.setEnabled(False)
        self.prioritize_button.setEnabled(False)
        self.submission_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(args)
        # The orchestrator resolves a relative config path (and every report
        # path) against CWD; without this pin, Settings edits a config.yaml
        # the engine never reads.
        self.process.setWorkingDirectory(str(ROOT_DIR))
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.process.setProcessEnvironment(self._qt_environment(env))
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)
        self.process.start()
        self._run_started_at = time.monotonic()
        self._elapsed_timer.start()
        self._poll_timer.start()

    def _process_error(self, error):
        """A failed start never fires `finished` — without this the Run
        button would stay disabled forever."""
        if error != QProcess.FailedToStart:
            # Crashes still emit `finished`; just mark the log now.
            self.log_output.appendHtml(
                f'<span style="color:#f87171">process error: '
                f"{html_escape(self.process.errorString() if self.process else str(error))}"
                "</span>"
            )
            return
        self._stop_run_timers()
        detail = self.process.errorString() if self.process else str(error)
        self._restore_run_buttons()
        self._set_status("error", "Failed to start")
        self.log_output.appendHtml(
            f'<span style="color:#f87171">failed to start orchestrator: '
            f"{html_escape(detail)}</span>"
        )
        QMessageBox.warning(
            self, "Run Failed",
            f"Could not start the orchestrator:\n{detail}",
        )

    def stop_scan(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(2000):
                self.process.kill()
        self._stop_run_timers()

    def _read_stdout(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.log_output.appendPlainText(text.rstrip())

    def _read_stderr(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        self.log_output.appendHtml(
            f'<span style="color:#f87171">{html_escape(text.rstrip())}</span>'
        )

    def _process_finished(self, exit_code: int, _status):
        self._stop_run_timers()
        was_report = self.running_report
        self.running_report = False
        self.load_results()
        if (
            not was_report
            and exit_code == 0
            and (self.report_after_process or not self._report_path().exists())
        ):
            self.report_after_process = False
            self.generate_report()
            return

        self.report_after_process = False
        if exit_code == 0:
            self._set_status("ok", "Completed", "Results loaded")
            self.log_output.appendPlainText("── run finished successfully ──")
        else:
            self._set_status("error", f"Failed (exit {exit_code})", f"Failed (exit {exit_code})")
            self.log_output.appendHtml(
                f'<span style="color:#f87171">── run failed with exit code '
                f"{exit_code} ──</span>"
            )
        self._restore_run_buttons()
        self._sync_mode()

    def load_results(self):
        target = self.target_input.text().strip()
        if not target:
            return
        base = self.output_dir / self._target_output_name()
        state_dir = base / "state"
        module = self._read_json(state_dir / "module.json", {})
        assets = self._read_json(state_dir / "assets.json", {"nodes": []})
        findings = self._read_json(state_dir / "findings.json", {"findings": []})
        evidence = self._read_json(state_dir / "evidence.json", {"items": []})
        summary_bundle = self._read_json(self._summary_path(), {})

        self.assets_value.setText(str(len(assets.get("nodes", []))))
        self.relations_value.setText(str(len(assets.get("edges", []))))
        self.findings_value.setText(str(len(findings.get("findings", []))))
        self.evidence_value.setText(str(len(evidence.get("items", []))))
        stats = module.get("stats", {})
        self.requests_value.setText(str(stats.get("total_requests", "-")))
        self.completed_value.setText(str(len(module.get("completed", []))))
        self.skipped_value.setText(str(len(module.get("skipped", []))))
        self.blocked_value.setText(str(len(module.get("blocked", []))))
        self.incomplete_value.setText(str(self._incomplete_count(module)))
        active_count = sum(1 for mid, entry in MODULE_REGISTRY.items() if entry.get("active"))
        self.active_value.setText(str(active_count))
        risk = summary_bundle.get("risk", {})
        self.max_risk_value.setText(str(risk.get("max_score", "-")))
        self.critical_high_value.setText(str(risk.get("critical_high", "-")))

        report_path = self._report_path()
        report_display = self._display_path(report_path) if report_path.exists() else "-"
        self.report_value.setText(report_display)
        self.report_value.setToolTip(str(report_path) if report_path.exists() else "")
        self.report_path_label.setText(report_display if report_path.exists() else "No report generated yet")
        self.report_path_label.setToolTip(str(report_path) if report_path.exists() else "")
        attack_plan_path = self._attack_plan_path()
        attack_plan_display = self._display_path(attack_plan_path) if attack_plan_path.exists() else ""
        self.attack_plan_path_label.setText(
            attack_plan_display if attack_plan_path.exists() else "No AI attack plan generated yet"
        )
        self.attack_plan_path_label.setToolTip(str(attack_plan_path) if attack_plan_path.exists() else "")
        self._load_findings(findings.get("findings", []))
        self._load_assets(assets.get("nodes", []))
        self._load_modules(module)
        self._load_evidence(evidence.get("items", []))
        self._load_submissions()
        self._load_summary_json(summary_bundle)
        self.current_assets = assets
        self.current_module = module
        self.current_evidence = evidence
        self._update_operation_context()
        self.refresh_graph()
        self._load_attack_graph()
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")
            self.report_preview.setMarkdown(report_text)
            self.report_raw.setPlainText(report_text)
        else:
            message = "No report generated yet. Use the Report action or enable automatic report generation."
            self.report_preview.setPlainText(message)
            self.report_raw.setPlainText("")
        if attack_plan_path.exists():
            self.attack_plan_preview.setMarkdown(attack_plan_path.read_text(errors="replace"))
        else:
            self.attack_plan_preview.setPlainText(
                "No AI attack plan generated yet. Run AI Attack Plan after OSINT collection."
            )

    def _update_operation_context(self):
        if not hasattr(self, "operation_target_label"):
            return

        target = self.target_input.text().strip() if hasattr(self, "target_input") else ""
        mode = self.mode_combo.currentText() if hasattr(self, "mode_combo") else "-"
        module = self.module_combo.currentData() if hasattr(self, "module_combo") else "-"
        if mode != "Single module":
            module = "orchestrated chain"

        self.operation_target_label.setText(f"Target: {target or '-'}")
        engagement = ""
        if hasattr(self, "pentest_check") and self.pentest_check.isChecked():
            risk = self.risk_combo.currentText() if hasattr(self, "risk_combo") else "LOW"
            engagement = f" | Pentest: {risk}"
        backend = getattr(self, "_tools_backend_mode", "local")
        self.operation_mode_label.setText(
            f"Mode: {mode} | Module: {module}{engagement} | "
            f"Backend: {backend} | Config: {self.config_path.name}"
        )
        ready, llm_message = self._llm_status()
        self.llm_status_label.setText(llm_message)
        self.llm_status_label.setProperty("ready", ready)
        self.llm_status_label.style().unpolish(self.llm_status_label)
        self.llm_status_label.style().polish(self.llm_status_label)
        if hasattr(self, "llm_settings_status"):
            self.llm_settings_status.setText(llm_message)
            self.llm_settings_status.setProperty("ready", ready)
            self.llm_settings_status.style().unpolish(self.llm_settings_status)
            self.llm_settings_status.style().polish(self.llm_settings_status)

        self.config_chip.setText(self.config_path.name)
        self.config_chip.setToolTip(str(self.config_path))
        self.output_chip.setText(self._display_path(self.output_dir, 3))
        self.output_chip.setToolTip(str(self.output_dir))
        self.status_bar_label.setText(
            f"config: {self.config_path}   ·   output: {self.output_dir}"
        )

        module_state = self.current_module if isinstance(self.current_module, dict) else {}
        completed = len(module_state.get("completed", []))
        skipped = len(module_state.get("skipped", []))
        incomplete = self._incomplete_count(module_state)
        total = max(len(get_all_module_ids()), 1)
        progress = min(100, int((completed / total) * 100))
        self.progress_bar.setValue(progress)
        suffix = f", {incomplete} incomplete" if incomplete else ""
        self.progress_bar.setFormat(f"{completed}/{total} modules complete{suffix}")

        if self.process and self.process.state() != QProcess.NotRunning:
            return
        if completed or skipped:
            self.operation_state_label.setText("Results loaded")
        else:
            self.operation_state_label.setText("Ready")

        asset_count = len(self.current_assets.get("nodes", [])) if isinstance(self.current_assets, dict) else 0
        edge_count = len(self.current_assets.get("edges", [])) if isinstance(self.current_assets, dict) else 0
        evidence_count = len(self.current_evidence.get("items", [])) if isinstance(self.current_evidence, dict) else 0
        self.exposure_label.setText(
            f"Exposure map: {asset_count} assets / {edge_count} relations / {evidence_count} evidence items"
        )

    def _display_path(self, path: Path, max_parts: int = 4) -> str:
        parts = path.parts
        if len(parts) <= max_parts:
            return str(path)
        return str(Path("...").joinpath(*parts[-max_parts:]))

    def _target_output_name(self) -> str:
        target = self.target_input.text().strip()
        parsed = urlparse(target if "://" in target else f"//{target}")
        return parsed.hostname or target.rstrip("/").split("/")[0]

    def _report_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_report.md"

    def _attack_plan_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_attack_plan.md"

    def _summary_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_summary.json"

    def _load_findings(self, findings: list[dict]):
        self.current_findings = list(findings)
        self._triage = self._read_triage()
        self._apply_finding_filter()

    def _apply_finding_filter(self, *_args):
        """Reduce the findings table to the rows matching the filter bar."""
        search = self.finding_search.text().strip().lower()
        severity = self.finding_severity_combo.currentText()
        confidence = self.finding_confidence_combo.currentText()
        verified_mode = self.finding_verified_combo.currentIndex()
        triage_mode = self.finding_triage_combo.currentIndex()
        selected: list[dict] = []
        for finding in self.current_findings:
            if severity != "All severities" and \
                    str(finding.get("severity", "")).upper() != severity:
                continue
            if confidence != "All confidence" and \
                    str(finding.get("confidence", "")).upper() != confidence:
                continue
            is_verified = bool(finding.get("verified"))
            if verified_mode == 1 and not is_verified:
                continue
            if verified_mode == 2 and is_verified:
                continue
            verdict = self._verdict_of(finding)
            if triage_mode == 1 and verdict:
                continue
            if triage_mode == 2 and verdict != "true_positive":
                continue
            if triage_mode == 3 and verdict != "false_positive":
                continue
            if triage_mode == 4 and verdict != "out_of_scope":
                continue
            if search:
                haystack = " ".join([
                    str(finding.get("id", "")),
                    str(finding.get("title", "")),
                    str(finding.get("category", "")),
                    str(finding.get("description", "")),
                ]).lower()
                if search not in haystack:
                    continue
            selected.append(finding)
        self._filtered_findings = selected
        self._populate_findings(selected)

    def _finding_sort_key(self, column: int):
        def key(finding: dict):
            if column == 0:
                return str(finding.get("id", ""))
            if column == 1:
                return _priority_rank(finding.get("priority"))
            if column == 2:
                return SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), -1)
            if column == 3:
                return int(finding.get("risk_score") or 0)
            if column == 4:
                return CONFIDENCE_RANK.get(str(finding.get("confidence", "")).upper(), -1)
            if column == 7:
                return str(finding.get("module_id", "")).lower()
            if column == 8:
                return str(self._verdict_of(finding))
            if column == 9:
                return ", ".join(finding.get("asset_keys", [])).lower()
            if column == 6:
                return str(finding.get("category", "")).lower()
            return str(finding.get("title", "")).lower()

        return key

    def _sort_findings(self, column: int):
        order = Qt.DescendingOrder if column == 3 else Qt.AscendingOrder
        if self._findings_sort[0] == column:
            order = (
                Qt.AscendingOrder
                if self._findings_sort[1] == Qt.DescendingOrder
                else Qt.DescendingOrder
            )
        self._findings_sort = [column, order]
        self.findings_table.horizontalHeader().setSortIndicator(column, order)
        self._populate_findings(getattr(self, "_filtered_findings", self.current_findings))

    def _populate_findings(self, findings: list[dict]):
        # Keep the analyst's place: repopulating after a verdict/note used to
        # clear the selection and reset the detail pane mid-triage.
        previous = self._selected_finding()
        previous_id = str(previous.get("id", "")) if previous else ""
        scroll_value = self.findings_table.verticalScrollBar().value()

        column, order = self._findings_sort
        reverse = order == Qt.DescendingOrder
        ordered = sorted(findings, key=self._finding_sort_key(column), reverse=reverse)
        self.findings_table.setRowCount(len(ordered))
        for row, finding in enumerate(ordered):
            verdict = self._verdict_of(finding)
            values = [
                str(finding.get("id", "")),
                str(finding.get("priority") or ""),
                str(finding.get("severity") or ""),
                str(finding.get("risk_score") or 0),
                str(finding.get("confidence") or ""),
                str(finding.get("title") or ""),
                str(finding.get("category") or ""),
                str(finding.get("module_id") or ""),
                VERDICT_LABELS.get(verdict, verdict),
                ", ".join(finding.get("asset_keys", [])[:3]),
            ]
            # Sort keys: numeric rank where a string would sort wrong.
            sort_keys = [
                values[0],
                _priority_rank(values[1]),
                SEVERITY_RANK.get(values[2].upper(), -1),
                int(values[3] or 0),
                CONFIDENCE_RANK.get(values[4].upper(), -1),
                values[5], values[6], values[7], values[8], values[9],
            ]
            severity_color = SEVERITY_COLORS.get(values[2].upper())
            verdict_color = VERDICT_COLORS.get(verdict)
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, sort_keys[col])
                if col == 2 and severity_color:
                    item.setForeground(QColor(severity_color))
                    item.setFont(_bold_font())
                if col == 8 and verdict_color:
                    item.setForeground(QColor(verdict_color))
                self.findings_table.setItem(row, col, item)
        self.finding_count_label.setText(
            f"showing {len(ordered)} of {len(self.current_findings)}"
        )
        if previous_id:
            for row in range(self.findings_table.rowCount()):
                item = self.findings_table.item(row, 0)
                if item and item.text() == previous_id:
                    self.findings_table.selectRow(row)
                    self.findings_table.verticalScrollBar().setValue(scroll_value)
                    break
        self._update_finding_detail()

    def _verdict_of(self, finding: dict) -> str:
        entry = self._triage.get(str(finding.get("id", "")), {})
        if isinstance(entry, dict):
            return str(entry.get("verdict", ""))
        return ""

    def _selected_finding(self) -> dict | None:
        row = self.findings_table.currentRow()
        if row < 0:
            return None
        item = self.findings_table.item(row, 0)
        if not item:
            return None
        finding_id = item.text()
        for finding in self.current_findings:
            if str(finding.get("id", "")) == finding_id:
                return finding
        return None

    def _update_finding_detail(self):
        if not hasattr(self, "finding_detail"):
            return
        finding = self._selected_finding()
        if not finding:
            self.finding_detail.setPlainText(
                "Select a finding to see its description, remediation and evidence."
            )
            if hasattr(self, "verdict_chip"):
                self.verdict_chip.setText("Untriaged")
                self.verdict_chip.setProperty("verdict", "")
                self.verdict_chip.style().unpolish(self.verdict_chip)
                self.verdict_chip.style().polish(self.verdict_chip)
            return
        verdict = self._verdict_of(finding)
        if hasattr(self, "verdict_chip"):
            chip_text = VERDICT_LABELS.get(verdict, verdict) if verdict else "Untriaged"
            self.verdict_chip.setText(chip_text)
            self.verdict_chip.setProperty("verdict", verdict or "none")
            self.verdict_chip.style().unpolish(self.verdict_chip)
            self.verdict_chip.style().polish(self.verdict_chip)
        entry = self._triage.get(str(finding.get("id", "")), {})
        note = str(entry.get("note", "")) if isinstance(entry, dict) else ""
        lines = [
            f"{finding.get('id', '')}  —  "
            f"{finding.get('priority') or '-'} / "
            f"{finding.get('severity') or '-'} / "
            f"{finding.get('confidence') or '-'}  "
            f"(score {finding.get('risk_score', 0)})",
            f"Module: {finding.get('module_id', '-')}   "
            f"Category: {finding.get('category', '-')}   "
            f"Verified: {'yes' if finding.get('verified') else 'no'}",
            f"CWE: {', '.join(finding.get('cwe') or []) or '-'}   "
            f"OWASP: {finding.get('owasp') or '-'}",            f"Triage: {VERDICT_LABELS.get(verdict, verdict) or 'untriaged'}"
            + (f"   Note: {note}" if note else ""),
            "",
            str(finding.get("description") or "").strip(),
            "",
        ]
        remediation = str(finding.get("remediation") or "").strip()
        if remediation:
            lines += ["Remediation:", remediation, ""]
        inline = finding.get("evidence") or []
        if inline:
            lines.append("Evidence:")
            lines += [f"  - {item}" for item in inline[:12]]
            if len(inline) > 12:
                lines.append(f"  ... {len(inline) - 12} more")
            lines.append("")
        refs = finding.get("evidence_refs") or []
        if refs:
            lines.append("Evidence refs: " + ", ".join(str(r) for r in refs))
            lines.append("(double-click a row in the Evidence tab to open files)")
            lines.append("")
        assets = finding.get("asset_keys") or []
        if assets:
            lines.append("Assets:")
            lines += [f"  - {key}" for key in assets]
        verification = finding.get("verification")
        if verification:
            lines += ["", "Verification detail:", json.dumps(verification, indent=2, default=str)]
        self.finding_detail.setPlainText("\n".join(lines))

    def _findings_context_menu(self, pos):
        findings = self._selected_findings()
        if not findings:
            return
        finding = findings[0]
        count = len(findings)
        menu = QMenu(self)
        copy_action = menu.addAction(
            "Copy finding ID" if count == 1 else f"Copy finding ID ({count} findings)"
        )
        evidence_action = menu.addAction("Open evidence file")
        menu.addSeparator()
        verdict_menu = menu.addMenu(
            "Set verdict" if count == 1 else f"Set verdict on {count} findings"
        )
        verdict_actions = {
            verdict_menu.addAction(label): verdict
            for verdict, label in (
                ("true_positive", "True positive"),
                ("false_positive", "False positive"),
                ("out_of_scope", "Out of scope"),
            )
        }
        clear_action = verdict_menu.addAction("Clear verdict")
        note_action = menu.addAction("Edit triage note...")
        chosen = menu.exec(self.findings_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is copy_action:
            if count == 1:
                QApplication.clipboard().setText(str(finding.get("id", "")))
            else:
                QApplication.clipboard().setText(
                    "\n".join(str(f.get("id", "")) for f in findings)
                )
            self.statusBar().showMessage(f"Copied {count} finding id(s)", 3000)
        elif chosen is evidence_action:
            self._open_finding_evidence(finding)
        elif chosen is clear_action:
            for selected in findings:
                self._set_finding_verdict(selected, "", refilter=False)
            self._apply_finding_filter()
            if count > 1:
                self.statusBar().showMessage(
                    f"Cleared verdict on {count} findings", 4000
                )
        elif chosen in verdict_actions:
            verdict = verdict_actions[chosen]
            for selected in findings:
                self._set_finding_verdict(selected, verdict, refilter=False)
            self._apply_finding_filter()
            if count > 1:
                self.statusBar().showMessage(
                    f"{count} findings → {VERDICT_LABELS.get(verdict, verdict)}", 4000
                )
        elif chosen is note_action:
            self._edit_triage_note(finding)

    def _set_finding_verdict(self, finding: dict, verdict: str, refilter: bool = True):
        finding_id = str(finding.get("id", ""))
        if not finding_id:
            return
        entry = self._triage.setdefault(finding_id, {})
        if not isinstance(entry, dict):
            entry = self._triage[finding_id] = {}
        if verdict:
            entry["verdict"] = verdict
        else:
            entry.pop("verdict", None)
            if not entry:
                self._triage.pop(finding_id, None)
        self._write_triage()
        if refilter:
            self._apply_finding_filter()

    def _edit_triage_note(self, finding: dict):
        finding_id = str(finding.get("id", ""))
        entry = self._triage.get(finding_id, {})
        current = str(entry.get("note", "")) if isinstance(entry, dict) else ""
        note, accepted = QInputDialog.getText(
            self, "Triage note", f"Note for {finding_id}:", text=current
        )
        if not accepted:
            return
        stored = self._triage.setdefault(finding_id, {})
        if not isinstance(stored, dict):
            stored = self._triage[finding_id] = {}
        if note.strip():
            stored["note"] = note.strip()
        else:
            stored.pop("note", None)
            if not stored:
                self._triage.pop(finding_id, None)
        self._write_triage()
        self._apply_finding_filter()

    def _open_finding_evidence(self, finding: dict):
        refs = {str(ref) for ref in (finding.get("evidence_refs") or [])}
        target_dir = self.output_dir / self._target_output_name()
        for item in self.current_evidence.get("items", []):
            if str(item.get("id", "")) not in refs:
                continue
            path = target_dir / str(item.get("path", ""))
            if path.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
                return
        QMessageBox.information(
            self, "No Evidence File",
            "This finding has no evidence file on disk (only inline text or refs "
            "that no longer resolve).",
        )

    def _triage_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_triage.json"

    def _read_triage(self) -> dict:
        data = self._read_json(self._triage_path(), {})
        return data if isinstance(data, dict) else {}

    def _write_triage(self):
        path = self._triage_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self._triage, indent=2, sort_keys=True))
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))


    def _load_assets(self, assets: list[dict]):
        self.assets_table.setSortingEnabled(False)
        self.assets_table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            values = [
                asset.get("type", ""),
                asset.get("value", ""),
                asset.get("confidence", ""),
                ", ".join(asset.get("sources", [])),
            ]
            for col, value in enumerate(values):
                self.assets_table.setItem(row, col, QTableWidgetItem(value))
        self.assets_table.setSortingEnabled(True)
        self._apply_table_filter(self.assets_table)

    def _incomplete_count(self, module: dict) -> int:
        """Modules whose latest run timed out or errored without ever finishing.

        A deadline kill lands in neither `completed` nor `skipped`, so before
        this the run read as "not started yet": invisible in every metric and
        the progress bar denominator treated it as pending forever.
        """
        completed = set(module.get("completed", []))
        skipped = {
            item.get("module_id") for item in module.get("skipped", [])
            if isinstance(item, dict)
        }
        blocked = {
            item.get("module_id") for item in module.get("blocked", [])
            if isinstance(item, dict)
        }
        resolved = completed | skipped | blocked
        count = 0
        seen: set[str] = set()
        for run in reversed(module.get("runs", [])):
            module_id = run.get("module_id", "")
            if not module_id or module_id in seen:
                continue
            seen.add(module_id)
            status = str(run.get("status", "")).lower()
            if status in ("timeout", "error", "failed", "incomplete") and module_id not in resolved:
                count += 1
        return count

    def _load_modules(self, module: dict):
        latest_runs = {}
        for run in module.get("runs", []):
            latest_runs[run.get("module_id", "")] = run
        skipped = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("skipped", [])
            if isinstance(item, dict)
        }
        blocked = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("blocked", [])
            if isinstance(item, dict)
        }
        completed = set(module.get("completed", []))
        self.modules_table.setSortingEnabled(False)
        module_ids = get_all_module_ids()
        self.modules_table.setRowCount(len(module_ids))
        for row, module_id in enumerate(module_ids):
            entry = MODULE_REGISTRY[module_id]
            run = latest_runs.get(module_id, {})
            status = run.get("status", "")
            if not status:
                if module_id in completed:
                    status = "completed"
                elif module_id in skipped:
                    status = "skipped"
                elif module_id in blocked:
                    status = "blocked"
                else:
                    status = "pending"
            values = [
                str(entry.get("stage", "")),
                module_id,
                status,
                entry.get("detectability", ""),
                str(run.get("requests", 0)),
                str(run.get("assets_added", 0)),
                str(run.get("findings_added", 0)),
                run.get("error") or skipped.get(module_id) or blocked.get(module_id) or "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col in (0, 4, 5, 6):
                    item.setData(Qt.UserRole, int(value or 0))
                if col == 2:
                    color = STATUS_COLORS.get(status.lower())
                    if color:
                        item.setForeground(QColor(color))
                    if status.lower() in ("timeout", "error", "failed", "incomplete"):
                        item.setToolTip("coverage incomplete — run did not finish")
                if col == 7 and value:
                    item.setToolTip(str(value))
                self.modules_table.setItem(row, col, item)
        self.modules_table.setSortingEnabled(True)
        self._apply_table_filter(self.modules_table)

    def _load_evidence(self, items: list[dict]):
        self.evidence_table.setSortingEnabled(False)
        self.evidence_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                item.get("id", ""),
                item.get("module_id", ""),
                item.get("type", ""),
                str(item.get("subject", "")),
                item.get("path", ""),
            ]
            for col, value in enumerate(values):
                self.evidence_table.setItem(row, col, QTableWidgetItem(value))
        self.evidence_table.setSortingEnabled(True)
        self._apply_table_filter(self.evidence_table)

    def _load_submissions(self):
        target = self._target_output_name()
        submission_dir = self.output_dir / target / "submissions"
        files = sorted(submission_dir.glob("*.md")) if submission_dir.exists() else []
        self.submissions_table.setSortingEnabled(False)
        self.submissions_table.setRowCount(len(files))
        for row, path in enumerate(files):
            values = [path.name, str(path.stat().st_size), str(path)]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setData(Qt.UserRole, path.stat().st_size)
                self.submissions_table.setItem(row, col, item)
        self.submissions_table.setSortingEnabled(True)
        self._apply_table_filter(self.submissions_table)

    def _load_summary_json(self, summary: dict):
        if summary:
            self.summary_json.setPlainText(json.dumps(summary, indent=2, default=str))
        else:
            self.summary_json.setPlainText("No summary JSON generated yet.")

    def _load_settings_form(self):
        config = self._read_config()
        llm = config.get("llm", {})
        if hasattr(self, "llm_model_combo"):
            self.llm_model_combo.setCurrentText(str(llm.get("model", "")))
            self.llm_api_key_input.setText(str(llm.get("api_key", "")))
            self.llm_temperature_spin.setValue(float(llm.get("temperature", 0.1) or 0.1))
            self.llm_max_tokens_spin.setValue(int(llm.get("max_tokens", 2000) or 2000))

        target = config.get("target", {})
        if hasattr(self, "config_target_domain_input"):
            self.config_target_domain_input.setText(str(target.get("domain", "")))
            self._set_combo_value(self.config_mode_combo, str(target.get("mode", "passive")))

        tools_cfg = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
        if hasattr(self, "tools_backend_combo"):
            backend = str(tools_cfg.get("backend", "local") or "local").strip().lower()
            index = self.tools_backend_combo.findText(backend)
            self.tools_backend_combo.setCurrentIndex(index if index >= 0 else 0)
            self.tools_image_input.setText(str(tools_cfg.get("image", "") or ""))

        detectability = config.get("detectability", {})
        if hasattr(self, "config_default_detectability_combo"):
            self._set_combo_value(
                self.config_default_detectability_combo,
                str(detectability.get("default", "low")),
            )

        modules = config.get("modules", {})
        if hasattr(self, "config_auto_run_check"):
            self.config_auto_run_check.setChecked(bool(modules.get("auto_run", True)))
            self.config_record_http_evidence_check.setChecked(bool(modules.get("record_http_evidence", True)))
            self.config_max_empty_spin.setValue(int(modules.get("max_consecutive_empty", 5) or 0))

        if hasattr(self, "module_timeout_spin"):
            self.module_timeout_spin.setValue(int(config.get("module_timeout", 300) or 300))
            budget = config.get("budget_limits") or {}
            self.budget_requests_spin.setValue(int(budget.get("max_requests", 0) or 0))
            self.budget_wall_clock_spin.setValue(int(budget.get("max_wall_clock_seconds", 0) or 0))
            self.budget_llm_spin.setValue(int(budget.get("max_llm_calls", 0) or 0))

        rate_limits = config.get("rate_limits", {})
        if hasattr(self, "rate_limit_inputs"):
            for name, fields in self.rate_limit_inputs.items():
                values = rate_limits.get(name, {})
                fields["concurrent"].setValue(int(values.get("concurrent", 1) or 1))
                fields["per_minute"].setValue(int(values.get("per_minute", 60) or 60))

        api_keys = config.get("api_keys", {})
        if hasattr(self, "api_key_inputs"):
            for service, key_input in self.api_key_inputs.items():
                key_input.setText(str(api_keys.get(service, "")))

        auth = config.get("auth", {})
        if hasattr(self, "auth_bearer_input"):
            self.auth_bearer_input.setText(str(auth.get("bearer_token", "")))
            self.auth_cookie_input.setText(str(auth.get("cookie", "")))
            self.auth_headers_input.setPlainText(self._headers_to_text(auth.get("headers", {})))
            self.auth_probe_backoff_spin.setValue(int(auth.get("probe_backoff_seconds", 10) or 0))

        if hasattr(self, "identities_table"):
            entries = auth.get("identities") or []
            if isinstance(entries, dict):
                entries = [
                    {"name": key, **value}
                    for key, value in entries.items()
                    if isinstance(value, dict)
                ]
            self._identity_records = [
                dict(entry) for entry in entries if isinstance(entry, dict)
            ]
            self._refresh_identities_table()

        xss = config.get("xss", {})
        if hasattr(self, "xss_browser_confirm_check"):
            self.xss_browser_confirm_check.setChecked(bool(xss.get("browser_confirm", True)))
            self.xss_max_points_spin.setValue(int(xss.get("max_points", 80) or 80))
            self.xss_dalfox_timeout_spin.setValue(int(xss.get("dalfox_timeout", 600) or 600))
            if hasattr(self, "xss_dalfox_blind_oob_check"):
                self.xss_dalfox_blind_oob_check.setChecked(bool(xss.get("dalfox_blind_oob", False)))
                try:
                    self.xss_dalfox_rate_spin.setValue(int(xss.get("dalfox_rate_limit", 0) or 0))
                except (TypeError, ValueError):
                    self.xss_dalfox_rate_spin.setValue(0)

        nuclei = config.get("nuclei", {})
        if hasattr(self, "nuclei_full_cve_check"):
            self.nuclei_full_cve_check.setChecked(bool(nuclei.get("full_cve_on_confirmed_apex", True)))

        kr_cfg = ((config.get("modules", {}) or {}).get("content_discovery", {})
                  or {}).get("kiterunner", {})
        kr_cfg = kr_cfg if isinstance(kr_cfg, dict) else {}
        if hasattr(self, "kr_enabled_check"):
            self.kr_enabled_check.setChecked(bool(kr_cfg.get("enabled", True)))
            self.kr_wordlist_input.setText(str(kr_cfg.get("wordlist", "") or ""))
            try:
                self.kr_max_routes_spin.setValue(int(kr_cfg.get("max_routes", 1500) or 1500))
            except (TypeError, ValueError):
                self.kr_max_routes_spin.setValue(1500)
            try:
                self.kr_max_targets_spin.setValue(int(kr_cfg.get("max_targets", 2) or 2))
            except (TypeError, ValueError):
                self.kr_max_targets_spin.setValue(2)

        sast_cfg = config.get("semgrep", {})
        sast_cfg = sast_cfg if isinstance(sast_cfg, dict) else {}
        if hasattr(self, "semgrep_enabled_check"):
            self.semgrep_enabled_check.setChecked(bool(sast_cfg.get("enabled", True)))
            self.semgrep_rules_input.setText(str(sast_cfg.get("rules", "") or ""))

        ssrf_cfg = ((config.get("modules", {}) or {}).get("ssrf_scan", {})
                    or {})
        ssrf_cfg = ssrf_cfg if isinstance(ssrf_cfg, dict) else {}
        if hasattr(self, "ssrf_enabled_check"):
            self.ssrf_enabled_check.setChecked(bool(ssrf_cfg.get("enabled", True)))
            try:
                self.ssrf_max_points_spin.setValue(int(ssrf_cfg.get("max_points", 6) or 6))
            except (TypeError, ValueError):
                self.ssrf_max_points_spin.setValue(6)

        crawl_cfg = ((config.get("crawl", {}) or {}).get("browser", {}) or {})
        crawl_cfg = crawl_cfg if isinstance(crawl_cfg, dict) else {}
        if hasattr(self, "crawl_enabled_check"):
            self.crawl_enabled_check.setChecked(bool(crawl_cfg.get("enabled", True)))
            for widget, key, default in (
                    (self.crawl_max_pages_spin, "max_targets", 8),
                    (self.crawl_depth_spin, "depth", 1),
                    (self.crawl_max_identities_spin, "max_identities", 2)):
                try:
                    widget.setValue(int(crawl_cfg.get(key, default) or default))
                except (TypeError, ValueError):
                    widget.setValue(default)

        logic_cfg = ((config.get("modules", {}) or {}).get("business_logic", {})
                     or {})
        logic_cfg = logic_cfg if isinstance(logic_cfg, dict) else {}
        if hasattr(self, "logic_enabled_check"):
            self.logic_enabled_check.setChecked(bool(logic_cfg.get("enabled", True)))
            try:
                self.logic_max_probes_spin.setValue(int(logic_cfg.get("max_probes", 12) or 12))
            except (TypeError, ValueError):
                self.logic_max_probes_spin.setValue(12)

        sqli_scan = config.get("modules", {}).get("sqli_scan", {})
        if hasattr(self, "sqli_oast_check") and isinstance(sqli_scan, dict):
            self.sqli_oast_check.setChecked(bool(sqli_scan.get("oast", True)))

        fast_scan = config.get("fast_scan", {})
        if hasattr(self, "fast_scan_paths_input"):
            self.fast_scan_paths_input.setPlainText(self._list_to_text(fast_scan.get("paths", [])))
            self.fast_scan_timeout_spin.setValue(int(fast_scan.get("timeout", 4) or 4))
            self.fast_scan_concurrency_spin.setValue(int(fast_scan.get("concurrency", 8) or 8))
            self.fast_scan_max_paths_spin.setValue(int(fast_scan.get("max_paths", 20) or 20))

        oob = config.get("oob", {})
        if hasattr(self, "oob_callback_domain_input"):
            if hasattr(self, "oob_mode_combo"):
                mode_index = self.oob_mode_combo.findData(str(oob.get("mode", "") or ""))
                self.oob_mode_combo.setCurrentIndex(mode_index if mode_index >= 0 else 0)
            if hasattr(self, "oob_enabled_check"):
                # Absent key means enabled (engine default); only an
                # explicit false disables.
                self.oob_enabled_check.setChecked(bool(oob.get("enabled", True)))
            self.oob_callback_domain_input.setText(str(oob.get("callback_domain", "")))
            self.oob_server_url_input.setText(str(oob.get("server_url", "")))
            self.oob_poll_url_input.setText(str(oob.get("poll_url", "")))
            self.oob_token_input.setText(str(oob.get("token", "")))
            self.oob_poll_interval_spin.setValue(int(oob.get("poll_interval", 2) or 2))
            self.oob_poll_timeout_spin.setValue(int(oob.get("poll_timeout", 30) or 30))

        self._load_raw_config_editor()
        self._load_tools_requirements_preview()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._update_operation_context()

    def _save_settings_form(self):
        config = self._read_config()

        if hasattr(self, "llm_model_combo"):
            config.setdefault("llm", {})
            config["llm"].update({
                "model": self.llm_model_combo.currentText().strip(),
                "api_key": self.llm_api_key_input.text().strip(),
                "temperature": self.llm_temperature_spin.value(),
                "max_tokens": self.llm_max_tokens_spin.value(),
            })

        if hasattr(self, "config_target_domain_input"):
            config.setdefault("target", {})
            config["target"].update({
                "domain": self.config_target_domain_input.text().strip(),
                "mode": self.config_mode_combo.currentText(),
            })

        if hasattr(self, "tools_backend_combo"):
            config.setdefault("tools", {})
            config["tools"].update({
                "backend": self.tools_backend_combo.currentText(),
                "image": self.tools_image_input.text().strip() or "osint-tools:latest",
            })

        if hasattr(self, "config_default_detectability_combo"):
            config.setdefault("detectability", {})
            config["detectability"].update({
                "default": self.config_default_detectability_combo.currentText(),
            })

        if hasattr(self, "config_auto_run_check"):
            config.setdefault("modules", {})
            config["modules"].update({
                "auto_run": self.config_auto_run_check.isChecked(),
                "max_consecutive_empty": self.config_max_empty_spin.value(),
                "record_http_evidence": self.config_record_http_evidence_check.isChecked(),
            })

        if hasattr(self, "module_timeout_spin"):
            config["module_timeout"] = self.module_timeout_spin.value()
            budget_limits = dict(
                config.get("budget_limits") if isinstance(config.get("budget_limits"), dict) else {}
            )
            budget_limits.update({
                "max_requests": self.budget_requests_spin.value(),
                "max_wall_clock_seconds": self.budget_wall_clock_spin.value(),
                "max_llm_calls": self.budget_llm_spin.value(),
            })
            config["budget_limits"] = budget_limits

        if hasattr(self, "rate_limit_inputs"):
            config.setdefault("rate_limits", {})
            for name, fields in self.rate_limit_inputs.items():
                config["rate_limits"][name] = {
                    "concurrent": fields["concurrent"].value(),
                    "per_minute": fields["per_minute"].value(),
                }

        if hasattr(self, "api_key_inputs"):
            config.setdefault("api_keys", {})
            for service, key_input in self.api_key_inputs.items():
                config["api_keys"][service] = key_input.text().strip()

        if hasattr(self, "auth_bearer_input"):
            config.setdefault("auth", {})
            config["auth"].update({
                "headers": self._text_to_headers(self.auth_headers_input.toPlainText()),
                "cookie": self.auth_cookie_input.text().strip(),
                "bearer_token": self.auth_bearer_input.text().strip(),
                "probe_backoff_seconds": self.auth_probe_backoff_spin.value(),
            })
            if hasattr(self, "identities_table"):
                self._sync_identity_records()
                config["auth"]["identities"] = [
                    record for record in self._identity_records if record.get("name")
                ]

        if hasattr(self, "xss_browser_confirm_check"):
            config.setdefault("xss", {})
            config["xss"].update({
                "browser_confirm": self.xss_browser_confirm_check.isChecked(),
                "max_points": self.xss_max_points_spin.value(),
                "dalfox_timeout": self.xss_dalfox_timeout_spin.value(),
            })
            if hasattr(self, "xss_dalfox_blind_oob_check"):
                config["xss"].update({
                    "dalfox_blind_oob": self.xss_dalfox_blind_oob_check.isChecked(),
                    "dalfox_rate_limit": self.xss_dalfox_rate_spin.value(),
                })

        if hasattr(self, "nuclei_full_cve_check"):
            config.setdefault("nuclei", {})
            config["nuclei"].update({
                "full_cve_on_confirmed_apex": self.nuclei_full_cve_check.isChecked(),
            })

        if hasattr(self, "sqli_oast_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            sqli_cfg = modules_cfg.get("sqli_scan")
            if not isinstance(sqli_cfg, dict):
                sqli_cfg = modules_cfg["sqli_scan"] = {}
            sqli_cfg["oast"] = self.sqli_oast_check.isChecked()

        if hasattr(self, "fast_scan_paths_input"):
            config.setdefault("fast_scan", {})
            config["fast_scan"].update({
                "paths": self._text_to_list(self.fast_scan_paths_input.toPlainText()),
                "timeout": self.fast_scan_timeout_spin.value(),
                "concurrency": self.fast_scan_concurrency_spin.value(),
                "max_paths": self.fast_scan_max_paths_spin.value(),
            })

        if hasattr(self, "oob_callback_domain_input"):
            config.setdefault("oob", {})
            config["oob"].update({
                "mode": self.oob_mode_combo.currentData() if hasattr(self, "oob_mode_combo") else "",
                "enabled": self.oob_enabled_check.isChecked() if hasattr(self, "oob_enabled_check") else True,
                "callback_domain": self.oob_callback_domain_input.text().strip(),
                "server_url": self.oob_server_url_input.text().strip(),
                "poll_url": self.oob_poll_url_input.text().strip(),
                "token": self.oob_token_input.text().strip(),
                "poll_interval": self.oob_poll_interval_spin.value(),
                "poll_timeout": self.oob_poll_timeout_spin.value(),
            })

        if hasattr(self, "kr_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            cd_cfg = modules_cfg.get("content_discovery")
            if not isinstance(cd_cfg, dict):
                cd_cfg = modules_cfg["content_discovery"] = {}
            cd_cfg["kiterunner"] = {
                "enabled": self.kr_enabled_check.isChecked(),
                "wordlist": self.kr_wordlist_input.text().strip() or "apiroutes-260227",
                "max_routes": self.kr_max_routes_spin.value(),
                "max_targets": self.kr_max_targets_spin.value(),
            }

        if hasattr(self, "semgrep_enabled_check"):
            config.setdefault("semgrep", {})
            config["semgrep"].update({
                "enabled": self.semgrep_enabled_check.isChecked(),
                "rules": self.semgrep_rules_input.text().strip() or "rules/semgrep",
            })

        if hasattr(self, "ssrf_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            ssrf_cfg = modules_cfg.get("ssrf_scan")
            if not isinstance(ssrf_cfg, dict):
                ssrf_cfg = modules_cfg["ssrf_scan"] = {}
            ssrf_cfg.update({
                "enabled": self.ssrf_enabled_check.isChecked(),
                "max_points": self.ssrf_max_points_spin.value(),
            })

        if hasattr(self, "crawl_enabled_check"):
            config.setdefault("crawl", {})
            crawl_cfg = config["crawl"]
            if not isinstance(crawl_cfg, dict):
                crawl_cfg = config["crawl"] = {}
            browser_cfg = crawl_cfg.get("browser")
            if not isinstance(browser_cfg, dict):
                browser_cfg = crawl_cfg["browser"] = {}
            browser_cfg.update({
                "enabled": self.crawl_enabled_check.isChecked(),
                "max_targets": self.crawl_max_pages_spin.value(),
                "depth": self.crawl_depth_spin.value(),
                "max_identities": self.crawl_max_identities_spin.value(),
            })

        if hasattr(self, "logic_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            logic_cfg = modules_cfg.get("business_logic")
            if not isinstance(logic_cfg, dict):
                logic_cfg = modules_cfg["business_logic"] = {}
            logic_cfg.update({
                "enabled": self.logic_enabled_check.isChecked(),
                "max_probes": self.logic_max_probes_spin.value(),
            })

        if self._write_config(config):
            self._load_raw_config_editor()
            self._refresh_key_status()
            self._refresh_tools_status()
            self._update_operation_context()
            self.status_label.setText("Settings saved")

    def _refresh_identities_table(self):
        if not hasattr(self, "identities_table"):
            return
        self.identities_table.setRowCount(len(self._identity_records))
        for row, record in enumerate(self._identity_records):
            for col, value in enumerate(self._identity_row_values(record)):
                self.identities_table.setItem(row, col, QTableWidgetItem(str(value)))

    @staticmethod
    def _identity_row_values(record: dict) -> list[str]:
        cookies = record.get("cookies") or {}
        if isinstance(cookies, dict):
            cookie_text = "; ".join(f"{key}={value}" for key, value in cookies.items())
        else:
            cookie_text = str(cookies)
        token = str(record.get("bearer_token") or record.get("token") or "")
        return [
            str(record.get("name", "")),
            token,
            cookie_text,
            str(record.get("verify_url", "")),
            str(record.get("success_marker", "")),
            str(record.get("role", "")),
        ]

    def _add_identity_row(self):
        # Table cells are edited without a binding model; sync first so a
        # rename typed into a row survives the table refresh below.
        self._sync_identity_records()
        used = {str(record.get("name", "")) for record in self._identity_records}
        index = len(self._identity_records) + 1
        name = f"identity_{index}"
        while name in used:
            index += 1
            name = f"identity_{index}"
        self._identity_records.append({"name": name})
        self._refresh_identities_table()
        self.identities_table.selectRow(len(self._identity_records) - 1)

    def _remove_identity_rows(self):
        self._sync_identity_records()
        rows = sorted(
            {index.row() for index in self.identities_table.selectedIndexes()},
            reverse=True,
        )
        for row in rows:
            if 0 <= row < len(self._identity_records):
                self._identity_records.pop(row)
        if rows:
            self._refresh_identities_table()

    def _sync_identity_records(self):
        """Read the table back into records, preserving unknown record keys."""
        records = []
        for row in range(self.identities_table.rowCount()):
            def cell(col: int) -> str:
                item = self.identities_table.item(row, col)
                return item.text().strip() if item else ""

            name = cell(0)
            if row < len(self._identity_records) and isinstance(self._identity_records[row], dict):
                record = dict(self._identity_records[row])
            else:
                record = {}
            # Keep one record per table row (even nameless ones) so row
            # indices stay aligned; save filters the empty ones out.
            record["name"] = name

            token = cell(1)
            if token:
                record["bearer_token"] = token
            else:
                record.pop("bearer_token", None)
                record.pop("token", None)

            cookies_text = cell(2)
            if cookies_text:
                cookies = {}
                for pair in cookies_text.split(";"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        cookies[key.strip()] = value.strip()
                if cookies:
                    record["cookies"] = cookies
                else:
                    record.pop("cookies", None)
            else:
                record.pop("cookies", None)

            for key, value in (
                ("verify_url", cell(3)),
                ("success_marker", cell(4)),
                ("role", cell(5)),
            ):
                if value:
                    record[key] = value
                else:
                    record.pop(key, None)
            records.append(record)
        self._identity_records = records

    def _load_raw_config_editor(self):
        if not hasattr(self, "raw_config_editor"):
            return
        if self.config_path.exists():
            self.raw_config_editor.setPlainText(self.config_path.read_text(errors="replace"))
        else:
            self.raw_config_editor.setPlainText("")

    def _save_raw_config_editor(self):
        text = self.raw_config_editor.toPlainText()
        try:
            parsed = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            QMessageBox.warning(self, "Invalid YAML", str(exc))
            return
        if not isinstance(parsed, dict):
            QMessageBox.warning(self, "Invalid YAML", "Config root must be a mapping.")
            return
        try:
            self.config_path.write_text(text)
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return
        self._load_settings_form()
        self.status_label.setText("Raw config applied")

    def _write_config(self, config: dict) -> bool:
        try:
            self.config_path.write_text(yaml.safe_dump(config, sort_keys=False))
            return True
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return False

    def _set_combo_value(self, combo: QComboBox, value: str):
        index = combo.findText(value)
        if index >= 0:
            combo.setCurrentIndex(index)
        elif combo.isEditable():
            combo.setCurrentText(value)

    def _headers_to_text(self, headers: dict) -> str:
        if not isinstance(headers, dict):
            return ""
        return "\n".join(f"{key}: {value}" for key, value in headers.items())

    def _text_to_headers(self, text: str) -> dict:
        headers = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                headers[key] = value
        return headers

    def _list_to_text(self, value) -> str:
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
        else:
            items = [str(item).strip() for item in (value or [])]
        return "\n".join(item for item in items if item)

    def _text_to_list(self, text: str) -> list[str]:
        items = []
        for line in text.replace(",", "\n").splitlines():
            item = line.strip()
            if item:
                items.append(item)
        return items

    def _open_evidence_cell(self, row: int, _col: int):
        item = self.evidence_table.item(row, 4)
        if not item:
            return
        path = self.output_dir / self._target_output_name() / item.text()
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _open_submission_cell(self, row: int, _col: int):
        item = self.submissions_table.item(row, 2)
        if item and Path(item.text()).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(item.text()))

    def refresh_graph(self):
        self._load_graph(self.current_assets)

    def _load_graph(self, assets: dict):
        graph = build_display_graph(
            assets,
            aggregate=self.graph_aggregate_check.isChecked(),
            aggregate_threshold=10,
            findings=self.current_findings,
        )
        nodes = graph["nodes"]
        edges = graph["edges"]
        meta = graph.get("meta", {})
        raw_nodes = meta.get("raw_nodes", len(nodes))
        raw_edges = meta.get("raw_edges", len(edges))
        self.graph_summary.setText(
            f"{raw_nodes} assets, {raw_edges} relations -> "
            f"{len(nodes)} displayed nodes, {len(edges)} displayed relations"
        )

        if not nodes:
            self.graph_view.setHtml(
                EMPTY_GRAPH_HTML.format(message="No asset graph available yet")
            )
            self._graph_render_key = None
            return

        html = render_gravis_html(
            graph,
            show_labels=self.graph_labels_check.isChecked(),
            show_edges=self.graph_edges_check.isChecked(),
            height=max(640, self.graph_view.height() - 20),
        )
        # Skip identical re-renders (load_results runs on many events) and
        # defer the paint so startup/refresh work doesn't block the UI thread.
        render_key = (
            len(nodes),
            len(edges),
            str(nodes[0].get("id", "")) if nodes else "",
            str(nodes[-1].get("id", "")) if nodes else "",
            self.graph_labels_check.isChecked(),
            self.graph_edges_check.isChecked(),
            self.graph_aggregate_check.isChecked(),
        )
        if getattr(self, "_graph_render_key", None) == render_key:
            return
        self._graph_render_key = render_key
        QTimer.singleShot(
            0,
            lambda: self.graph_view.setHtml(
                html, QUrl.fromLocalFile(str(ROOT_DIR))
            ),
        )

    def _attack_graph_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / "attack_graph.json"

    def _load_attack_graph(self):
        if not hasattr(self, "attack_graph_view"):
            return
        data = self._read_json(self._attack_graph_path(), {})
        self.current_attack_graph = data if isinstance(data, dict) else {}
        self.refresh_attack_graph()

    def refresh_attack_graph(self):
        if not hasattr(self, "attack_graph_view"):
            return
        graph = self.current_attack_graph if isinstance(self.current_attack_graph, dict) else {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        plan = graph.get("probe_plan") or {}

        if not nodes:
            self.attack_graph_summary.setText("No attack graph loaded")
            self.probe_plan_label.setText(
                "Probe plan: not recorded — enable Engagement → Attack graph "
                "(--pentest) and run."
            )
            self.probe_plan_table.setRowCount(0)
            self.attack_graph_view.setHtml(
                EMPTY_GRAPH_HTML.format(
                    message="No attack graph yet. Enable Engagement → Attack graph "
                            "(--pentest) and run the target."
                )
            )
            self._attack_render_key = None
            return

        proposed = sum(1 for edge in edges if (edge.get("attrs") or {}).get("proposed"))
        self.attack_graph_summary.setText(
            f"{len(nodes)} nodes, {len(edges)} edges ({proposed} proposed probe edge(s))"
        )
        if plan:
            self.probe_plan_label.setText(
                f"ceiling {plan.get('risk_ceiling', '?')} | "
                f"{plan.get('surfaces_considered', 0)} surfaces considered | "
                f"{plan.get('probes_proposed', 0)} probes proposed | "
                f"cap {plan.get('capped_at', '-')}"
            )
            reasons = sorted(
                (plan.get("not_proposed") or {}).items(),
                key=lambda kv: -int(kv[1] or 0),
            )
        else:
            self.probe_plan_label.setText("Probe plan: not recorded in this artifact")
            reasons = []
        self.probe_plan_table.setRowCount(len(reasons))
        for row, (reason, count) in enumerate(reasons):
            self.probe_plan_table.setItem(row, 0, QTableWidgetItem(str(reason)))
            count_item = QTableWidgetItem(str(count))
            count_item.setData(Qt.UserRole, int(count))
            self.probe_plan_table.setItem(row, 1, count_item)

        html = render_attack_html(
            graph,
            show_labels=len(nodes) <= 40,
            height=max(560, self.attack_graph_view.height() - 20),
        )
        render_key = (
            len(nodes),
            len(edges),
            str(nodes[0].get("id", "")) if nodes else "",
            str(nodes[-1].get("id", "")) if nodes else "",
        )
        if getattr(self, "_attack_render_key", None) == render_key:
            return
        self._attack_render_key = render_key
        QTimer.singleShot(
            0,
            lambda: self.attack_graph_view.setHtml(
                html, QUrl.fromLocalFile(str(ROOT_DIR))
            ),
        )

    def _read_json(self, path: Path, default):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return default

    def _read_config(self) -> dict:
        if not self.config_path.exists():
            return {}
        try:
            return yaml.safe_load(self.config_path.read_text()) or {}
        except (yaml.YAMLError, OSError):
            return {}

    def _refresh_key_status(self):
        vault = KeyVault(self._read_config())
        presence = vault.presence()
        self.keys_table.setRowCount(len(presence))
        for row, (service, info) in enumerate(presence.items()):
            values = [
                info.get("label", service),
                "yes" if info.get("present") else "no",
                info.get("masked", ""),
            ]
            for col, value in enumerate(values):
                self.keys_table.setItem(row, col, QTableWidgetItem(value))

    def _refresh_tools_status(self):
        if not hasattr(self, "tools_table"):
            return
        # Effective backend: shell env wins over the config file
        # (configure_tool_backend reads both; dotenv is loaded via agents).
        mode = configure_tool_backend(self._read_config())
        self._tools_backend_mode = mode
        rows: list[tuple[str, str, str, str]] = [
            (tool.name, ", ".join(tool.categories), tool.description,
             "docker" if tool.name in DOCKER_TOOLS else "local")
            for tool in TOOL_DEFINITIONS
        ]
        known = {name for name, _cats, _desc, _via in rows}
        for name in sorted(DOCKER_TOOLS - known):
            categories, purpose = EXTRA_CONTAINER_TOOLS.get(name, (["container"], "Toolchain image binary"))
            rows.append((name, ", ".join(categories), purpose, "docker"))
        rows.sort(key=lambda row: row[0])
        if hasattr(self, "tools_backend_label"):
            if mode == "docker":
                ready = tool_available("nuclei")
                state = "image ready" if ready else "image missing — build/pull osint-tools"
            else:
                state = "host binaries"
            self.tools_backend_label.setText(f"Backend: {mode} ({state})")
        self.tools_table.setRowCount(len(rows))
        for row, (name, categories, purpose, via) in enumerate(rows):
            ready = tool_available(name)
            values = [name, "yes" if ready else "no", via, categories, purpose]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setForeground(QColor("#4ade80" if ready else "#f87171"))
                self.tools_table.setItem(row, col, item)

    def _load_tools_requirements_preview(self):
        if not hasattr(self, "tools_requirements_preview"):
            return
        if TOOLS_REQUIREMENTS.exists():
            self.tools_requirements_preview.setPlainText(
                TOOLS_REQUIREMENTS.read_text(errors="replace")
            )
        else:
            self.tools_requirements_preview.setPlainText("tools_requirements.txt not found.")

    def open_tools_requirements(self):
        if not TOOLS_REQUIREMENTS.exists():
            QMessageBox.information(self, "Missing File", "tools_requirements.txt does not exist.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(TOOLS_REQUIREMENTS)))

    def install_missing_tools(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        # `--install-tools` still demands -t because the parser marks it
        # required; the target is irrelevant to the install itself.
        target = self.target_input.text().strip() or "localhost"
        args = [
            str(ORCHESTRATOR),
            "-t", target,
            "-o", str(self.output_dir),
            "-c", str(self.config_path),
            "--install-tools",
        ]
        self._start_process(args)

    def _qt_environment(self, env: dict):
        from PySide6.QtCore import QProcessEnvironment

        process_env = QProcessEnvironment()
        for key, value in env.items():
            process_env.insert(key, value)
        return process_env

    def _apply_style(self):
        app = QApplication.instance()
        if app is not None:
            app.setPalette(_dark_palette())
        theme_path = Path(__file__).with_name("theme.qss")
        try:
            qss = theme_path.read_text(encoding="utf-8")
        except OSError:
            return
        self.setStyleSheet(qss)


def main():
    app = QApplication(sys.argv)
    # Fusion gives consistent cross-platform rendering under our stylesheet
    # (macOS native style ignores large parts of a QSS theme).
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
