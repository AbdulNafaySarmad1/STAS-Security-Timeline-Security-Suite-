import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: int
    event_type: str
    process_name: str
    pid: int
    description: str
    severity: str
    attack_technique: str
    raw_data: Dict[str, Any]
    row_id: int = -1


class EventCard(QFrame):
    toggled = pyqtSignal()
    selected_changed = pyqtSignal()

    TYPE_COLORS = {
        "PROCESS": "#3B82F6",
        "FILE": "#EAB308",
        "REGISTRY": "#8B5CF6",
        "NETWORK": "#10B981",
        "PERSISTENCE": "#EF4444",
        "INJECTION": "#F97316",
    }

    TYPE_ICONS = {
        "PROCESS": "P",
        "FILE": "F",
        "REGISTRY": "R",
        "NETWORK": "N",
        "PERSISTENCE": "!",
        "INJECTION": "I",
    }

    SEVERITY_COLORS = {
        "LOW": "#10B981",
        "MED": "#EAB308",
        "MEDIUM": "#EAB308",
        "HIGH": "#F97316",
        "CRIT": "#EF4444",
        "CRITICAL": "#EF4444",
    }

    def __init__(self, event: TimelineEvent, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.event = event
        self.expanded = False
        self.setObjectName("eventCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._build()

    def _build(self) -> None:
        event_type = normalize_event_type(self.event.event_type)
        type_color = self.TYPE_COLORS.get(event_type, "#6B7280")
        severity = normalize_severity(self.event.severity)
        severity_color = self.SEVERITY_COLORS.get(severity, "#6B7280")

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(24)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 90))
        self.setGraphicsEffect(shadow)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)

        self.checkbox = QCheckBox()
        self.checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self.checkbox.stateChanged.connect(self.selected_changed.emit)
        header.addWidget(self.checkbox)

        icon = QLabel(self.TYPE_ICONS.get(event_type, "?"))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(30, 30)
        icon.setStyleSheet(
            f"background:{type_color}; color:#0D1117; border-radius:15px;"
            "font-size:13px; font-weight:900;"
        )
        header.addWidget(icon)

        main = QVBoxLayout()
        main.setSpacing(3)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        process = QLabel(self.event.process_name or "unknown")
        process.setObjectName("eventProcess")
        process.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        title_row.addWidget(process)

        pid = QLabel(f"PID {self.event.pid}" if self.event.pid >= 0 else "PID -")
        pid.setObjectName("eventPid")
        title_row.addWidget(pid)

        title_row.addStretch(1)

        timestamp = QLabel(format_timestamp(self.event.timestamp))
        timestamp.setObjectName("eventTimestamp")
        title_row.addWidget(timestamp)

        severity_badge = QLabel(severity)
        severity_badge.setObjectName("severityBadge")
        severity_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        severity_badge.setStyleSheet(
            f"background:{severity_color}; color:#0D1117; border-radius:8px;"
            "padding:3px 8px; font-size:11px; font-weight:900;"
        )
        title_row.addWidget(severity_badge)
        main.addLayout(title_row)

        description = QLabel(self.event.description or "(no description)")
        description.setObjectName("eventDescription")
        description.setWordWrap(True)
        description.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        main.addWidget(description)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(8)
        type_badge = QLabel(event_type)
        type_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        type_badge.setStyleSheet(
            f"border:1px solid {type_color}; color:{type_color}; border-radius:8px;"
            "padding:2px 8px; font-size:11px; font-weight:800;"
        )
        meta_row.addWidget(type_badge)

        if self.event.attack_technique:
            attack = QToolButton()
            attack.setText(self.event.attack_technique)
            attack.setCursor(Qt.CursorShape.PointingHandCursor)
            attack.setToolTip("Open MITRE ATT&CK technique")
            attack.setStyleSheet(
                "QToolButton { border:1px solid #F97316; color:#F97316; border-radius:8px;"
                "padding:2px 8px; font-size:11px; font-weight:900; background:rgba(249,115,22,0.10); }"
                "QToolButton:hover { background:rgba(249,115,22,0.20); }"
            )
            attack.clicked.connect(self.open_attack)
            meta_row.addWidget(attack)

        meta_row.addStretch(1)
        main.addLayout(meta_row)

        header.addLayout(main, 1)
        outer.addLayout(header)

        self.details = QLabel(json.dumps(self.event.raw_data, indent=2, sort_keys=True))
        self.details.setObjectName("eventDetails")
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setWordWrap(True)
        self.details.setVisible(False)
        outer.addWidget(self.details)

        self.setStyleSheet(
            "#eventCard { background:#161B22; border:1px solid #30363D; border-left:"
            f"4px solid {type_color}; border-radius:8px; }}"
            "#eventCard:hover { border-color:#F97316; }"
            "#eventProcess { color:#F8FAFC; font-size:14px; font-weight:800; }"
            "#eventPid, #eventTimestamp { color:#8B949E; font-size:12px; }"
            "#eventDescription { color:#CBD5E1; font-size:13px; }"
            "#eventDetails { background:#0D1117; color:#94A3B8; border:1px solid #30363D;"
            "border-radius:6px; padding:10px; font-family:Consolas, monospace; font-size:12px; }"
            "QCheckBox::indicator { width:15px; height:15px; }"
        )

    def mousePressEvent(self, event) -> None:
        child = self.childAt(event.pos())
        if child is not self.checkbox:
            self.set_expanded(not self.expanded)
        super().mousePressEvent(event)

    def set_expanded(self, expanded: bool) -> None:
        if self.expanded == expanded:
            return
        self.expanded = expanded
        self.details.setVisible(expanded)
        self.toggled.emit()

    def is_selected(self) -> bool:
        return self.checkbox.isChecked()

    def open_attack(self) -> None:
        technique = self.event.attack_technique.strip()
        if not technique:
            return
        path = technique.replace(".", "/")
        QDesktopServices.openUrl(QUrl(f"https://attack.mitre.org/techniques/{path}/"))


class EventGroup(QWidget):
    def __init__(self, title: str, events: List[TimelineEvent], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.title = title
        self.events = events
        self.cards: List[EventCard] = []
        self.collapsed = False
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(8)

        self.header = QToolButton()
        self.header.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.header.setArrowType(Qt.ArrowType.DownArrow)
        self.header.setText(self._header_text())
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header.clicked.connect(self.toggle)
        self.header.setStyleSheet(
            "QToolButton { background:#161B22; color:#F8FAFC; border:1px solid #30363D;"
            "border-radius:8px; padding:8px 10px; font-weight:900; text-align:left; }"
            "QToolButton:hover { border-color:#F97316; }"
        )
        layout.addWidget(self.header)

        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(18, 0, 0, 0)
        self.body_layout.setSpacing(8)
        layout.addWidget(self.body)

    def _header_text(self) -> str:
        crit = sum(1 for event in self.events if severity_rank(event.severity) >= 4)
        high = sum(1 for event in self.events if severity_rank(event.severity) == 3)
        return f"{self.title}  |  {len(self.events)} events  |  {crit} critical  |  {high} high"

    def add_card(self, card: EventCard) -> None:
        self.cards.append(card)
        self.body_layout.addWidget(card)

    def toggle(self) -> None:
        self.collapsed = not self.collapsed
        self.body.setVisible(not self.collapsed)
        self.header.setArrowType(Qt.ArrowType.RightArrow if self.collapsed else Qt.ArrowType.DownArrow)


class TimelineWidget(QWidget):
    PAGE_SIZE = 150

    def __init__(self, db_path: Optional[str] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db_path = db_path or self._default_db_path()
        self.all_events: List[TimelineEvent] = []
        self.filtered_events: List[TimelineEvent] = []
        self.visible_count = 0
        self.group_mode = "process"
        self.cards: List[EventCard] = []
        self.groups: List[EventGroup] = []
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.timeout.connect(self.apply_filters)
        self._build()

    def _build(self) -> None:
        self.setObjectName("timelineRoot")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        toolbar = QFrame()
        toolbar.setObjectName("timelineToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(12, 10, 12, 10)
        toolbar_layout.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter process, type, severity, description, ATT&CK")
        self.search.textChanged.connect(lambda: self._filter_timer.start(180))
        toolbar_layout.addWidget(self.search, 2)

        self.type_filter = QComboBox()
        self.type_filter.addItems(["ALL", "PROCESS", "FILE", "REGISTRY", "NETWORK", "PERSISTENCE", "INJECTION"])
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.type_filter)

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["ALL", "LOW", "MED", "HIGH", "CRIT"])
        self.severity_filter.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.severity_filter)

        self.group_filter = QComboBox()
        self.group_filter.addItems(["Group: Process", "Group: 1 Min", "Group: 5 Min", "Group: 1 Hr"])
        self.group_filter.currentIndexChanged.connect(self._change_group_mode)
        toolbar_layout.addWidget(self.group_filter)

        self.zoom_group = QButtonGroup(self)
        for label in ("1min", "5min", "1hr", "All"):
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setProperty("zoomButton", True)
            if label == "All":
                btn.setChecked(True)
            btn.clicked.connect(self.apply_filters)
            self.zoom_group.addButton(btn)
            toolbar_layout.addWidget(btn)

        suspicious = QPushButton("Jump to Suspicious")
        suspicious.clicked.connect(self.jump_to_suspicious)
        toolbar_layout.addWidget(suspicious)

        export = QPushButton("Export Selected")
        export.setMenu(self._export_menu())
        toolbar_layout.addWidget(export)

        root.addWidget(toolbar)

        self.summary = QLabel()
        self.summary.setObjectName("timelineSummary")
        root.addWidget(self.summary)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.verticalScrollBar().valueChanged.connect(self._maybe_load_more)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(6, 4, 10, 20)
        self.content_layout.setSpacing(10)
        self.content_layout.addStretch(1)
        self.scroll.setWidget(self.content)
        root.addWidget(self.scroll, 1)

        self.setStyleSheet(
            "#timelineRoot { background:#0D1117; color:#F8FAFC; }"
            "#timelineToolbar { background:#161B22; border:1px solid #30363D; border-radius:8px; }"
            "QLineEdit, QComboBox { background:#0D1117; color:#F8FAFC; border:1px solid #30363D;"
            "border-radius:6px; padding:7px 9px; selection-background-color:#F97316; }"
            "QLineEdit:focus, QComboBox:focus { border-color:#F97316; }"
            "QPushButton { background:#21262D; color:#F8FAFC; border:1px solid #30363D;"
            "border-radius:6px; padding:7px 10px; font-weight:800; }"
            "QPushButton:hover { border-color:#F97316; }"
            "QPushButton:checked { background:#F97316; color:#0D1117; border-color:#F97316; }"
            "#timelineSummary { color:#8B949E; padding:0 8px; font-size:12px; }"
            "QScrollArea { background:#0D1117; border:0; }"
            "QScrollBar:vertical { background:#0D1117; width:10px; }"
            "QScrollBar::handle:vertical { background:#30363D; border-radius:5px; min-height:42px; }"
            "QScrollBar::handle:vertical:hover { background:#F97316; }"
        )

    def _export_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#161B22; color:#F8FAFC; border:1px solid #30363D; }"
            "QMenu::item { padding:7px 18px; }"
            "QMenu::item:selected { background:#F97316; color:#0D1117; }"
        )
        menu.addAction("JSON", lambda: self.export_selected("json"))
        menu.addAction("Markdown", lambda: self.export_selected("md"))
        return menu

    def load_from_sqlite(self, db_path: Optional[str] = None, limit: Optional[int] = None) -> None:
        if db_path:
            self.db_path = db_path
        if not self.db_path or not os.path.exists(self.db_path):
            self.set_events([])
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        columns = self._table_columns(cur)
        select_sql = self._select_sql(columns, limit)
        rows = cur.execute(select_sql).fetchall()
        conn.close()
        self.set_events([self._row_to_event(row, columns) for row in rows])

    def set_events(self, events: Iterable[Dict[str, Any] | TimelineEvent]) -> None:
        parsed: List[TimelineEvent] = []
        for index, item in enumerate(events):
            if isinstance(item, TimelineEvent):
                parsed.append(item)
            else:
                parsed.append(self._dict_to_event(item, index))
        parsed.sort(key=lambda event: event.timestamp, reverse=True)
        self.all_events = parsed
        self.apply_filters()

    def apply_filters(self) -> None:
        query = self.search.text().strip().lower()
        type_filter = self.type_filter.currentText()
        severity_filter = self.severity_filter.currentText()
        zoom = self._current_zoom_seconds()

        events = self.all_events
        if zoom is not None and events:
            newest = max(event.timestamp for event in events)
            cutoff = newest - zoom * 1000
            events = [event for event in events if event.timestamp >= cutoff]

        if type_filter != "ALL":
            events = [event for event in events if normalize_event_type(event.event_type) == type_filter]
        if severity_filter != "ALL":
            events = [event for event in events if normalize_severity(event.severity) == severity_filter]
        if query:
            events = [event for event in events if self._matches_query(event, query)]

        self.filtered_events = events
        self.visible_count = min(self.PAGE_SIZE, len(self.filtered_events))
        self._render()

    def _render(self) -> None:
        self._clear_content()
        self.cards = []
        self.groups = []

        visible = self.filtered_events[: self.visible_count]
        grouped = self._group_events(visible)

        for title, events in grouped:
            group = EventGroup(title, events, self.content)
            self.groups.append(group)
            self.content_layout.insertWidget(self.content_layout.count() - 1, group)
            for event in events:
                card = EventCard(event, group)
                card.selected_changed.connect(self._update_summary)
                group.add_card(card)
                self.cards.append(card)

        self._update_summary()

    def _clear_content(self) -> None:
        while self.content_layout.count() > 1:
            item = self.content_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _maybe_load_more(self, value: int) -> None:
        bar = self.scroll.verticalScrollBar()
        if value < bar.maximum() - 400:
            return
        if self.visible_count >= len(self.filtered_events):
            return
        self.visible_count = min(self.visible_count + self.PAGE_SIZE, len(self.filtered_events))
        self._append_next_page()

    def _append_next_page(self) -> None:
        self._render()

    def jump_to_suspicious(self) -> None:
        if not self.filtered_events:
            return
        best_index = max(
            range(len(self.filtered_events)),
            key=lambda idx: (severity_rank(self.filtered_events[idx].severity), suspicious_weight(self.filtered_events[idx])),
        )
        if best_index >= self.visible_count:
            self.visible_count = min(len(self.filtered_events), best_index + self.PAGE_SIZE)
            self._render()
        if best_index < len(self.cards):
            card = self.cards[best_index]
            card.set_expanded(True)
            self._scroll_to_widget(card)

    def _scroll_to_widget(self, widget: QWidget) -> None:
        target = widget.mapTo(self.content, widget.rect().topLeft()).y()
        bar = self.scroll.verticalScrollBar()
        animation = QPropertyAnimation(bar, b"value", self)
        animation.setDuration(420)
        animation.setStartValue(bar.value())
        animation.setEndValue(max(0, target - 80))
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def export_selected(self, fmt: str) -> None:
        selected = [card.event for card in self.cards if card.is_selected()]
        if not selected:
            QMessageBox.information(self, "Export Selected", "Select one or more events first.")
            return

        extension = "json" if fmt == "json" else "md"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export selected events",
            f"timeline_events.{extension}",
            "JSON Files (*.json)" if fmt == "json" else "Markdown Files (*.md)",
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as handle:
            if fmt == "json":
                json.dump([event_to_dict(event) for event in selected], handle, indent=2)
            else:
                handle.write(events_to_markdown(selected))

    def _change_group_mode(self) -> None:
        text = self.group_filter.currentText()
        self.group_mode = {
            "Group: Process": "process",
            "Group: 1 Min": "1min",
            "Group: 5 Min": "5min",
            "Group: 1 Hr": "1hr",
        }.get(text, "process")
        self._render()

    def _group_events(self, events: List[TimelineEvent]) -> List[tuple[str, List[TimelineEvent]]]:
        groups: Dict[str, List[TimelineEvent]] = {}
        order: List[str] = []
        for event in events:
            key = self._group_key(event)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(event)
        return [(key, groups[key]) for key in order]

    def _group_key(self, event: TimelineEvent) -> str:
        if self.group_mode == "process":
            return event.process_name or "unknown process"
        seconds = {"1min": 60, "5min": 300, "1hr": 3600}.get(self.group_mode, 60)
        bucket = (event.timestamp // 1000 // seconds) * seconds
        start = datetime.fromtimestamp(bucket, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"{start} ({self.group_mode})"

    def _current_zoom_seconds(self) -> Optional[int]:
        checked = self.zoom_group.checkedButton()
        if checked is None:
            return None
        return {"1min": 60, "5min": 300, "1hr": 3600, "All": None}.get(checked.text(), None)

    def _matches_query(self, event: TimelineEvent, query: str) -> bool:
        haystack = " ".join(
            [
                event.process_name,
                event.event_type,
                event.severity,
                event.description,
                event.attack_technique,
                json.dumps(event.raw_data, sort_keys=True),
            ]
        ).lower()
        return query in haystack

    def _update_summary(self) -> None:
        selected = sum(1 for card in self.cards if card.is_selected())
        crit = sum(1 for event in self.filtered_events if severity_rank(event.severity) >= 4)
        high = sum(1 for event in self.filtered_events if severity_rank(event.severity) == 3)
        self.summary.setText(
            f"{len(self.filtered_events):,} matching events | {self.visible_count:,} rendered | "
            f"{crit:,} critical | {high:,} high | {selected:,} selected"
        )

    def _table_columns(self, cur: sqlite3.Cursor) -> set[str]:
        rows = cur.execute("PRAGMA table_info(events)").fetchall()
        return {row[1] for row in rows}

    def _select_sql(self, columns: set[str], limit: Optional[int]) -> str:
        selected = [
            "timestamp" if "timestamp" in columns else "0 AS timestamp",
            "event_type" if "event_type" in columns else ("type AS event_type" if "type" in columns else "NULL AS event_type"),
            "process_name" if "process_name" in columns else ("process AS process_name" if "process" in columns else "NULL AS process_name"),
            "pid" if "pid" in columns else "NULL AS pid",
            "description" if "description" in columns else ("details AS description" if "details" in columns else "NULL AS description"),
            "severity" if "severity" in columns else "NULL AS severity",
            "attack_technique" if "attack_technique" in columns else "NULL AS attack_technique",
            "raw_data" if "raw_data" in columns else ("details AS raw_data" if "details" in columns else "NULL AS raw_data"),
        ]
        if "id" in columns:
            selected.append("id AS row_id")
        else:
            selected.append("rowid AS row_id")
        sql = f"SELECT {', '.join(selected)} FROM events ORDER BY timestamp DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return sql

    def _row_to_event(self, row: sqlite3.Row, columns: set[str]) -> TimelineEvent:
        return self._dict_to_event(dict(row), int(row["row_id"]) if "row_id" in row.keys() else -1)

    def _dict_to_event(self, item: Dict[str, Any], fallback_id: int) -> TimelineEvent:
        raw = item.get("raw_data")
        if isinstance(raw, str):
            try:
                raw_data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                raw_data = {"raw": raw}
        elif isinstance(raw, dict):
            raw_data = raw
        else:
            raw_data = {}

        return TimelineEvent(
            timestamp=parse_timestamp(item.get("timestamp")),
            event_type=str(item.get("event_type") or item.get("type") or "PROCESS"),
            process_name=str(item.get("process_name") or item.get("process") or "unknown"),
            pid=parse_int(item.get("pid"), -1),
            description=str(item.get("description") or item.get("details") or ""),
            severity=normalize_severity(str(item.get("severity") or infer_severity(item))),
            attack_technique=str(item.get("attack_technique") or item.get("attack") or ""),
            raw_data=raw_data or {key: value for key, value in item.items() if key != "raw_data"},
            row_id=parse_int(item.get("row_id"), fallback_id),
        )

    def _default_db_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.abspath(os.path.join(here, "../../events.db")),
            os.path.abspath(os.path.join(here, "events.db")),
            os.path.abspath("events.db"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return candidates[0]


def normalize_event_type(value: str) -> str:
    upper = (value or "").upper()
    if "REG" in upper:
        return "REGISTRY"
    if "NET" in upper or "HTTP" in upper or "DNS" in upper or "SOCKET" in upper:
        return "NETWORK"
    if "FILE" in upper:
        return "FILE"
    if "PERSIST" in upper or "SERVICE" in upper or "AUTORUN" in upper:
        return "PERSISTENCE"
    if "INJECT" in upper or "REMOTE_THREAD" in upper or "WRITEPROCESS" in upper:
        return "INJECTION"
    return "PROCESS"


def normalize_severity(value: str) -> str:
    upper = (value or "LOW").upper()
    if upper in {"CRITICAL", "CRIT"}:
        return "CRIT"
    if upper in {"MEDIUM", "MED"}:
        return "MED"
    if upper in {"HIGH", "LOW"}:
        return upper
    return "LOW"


def severity_rank(value: str) -> int:
    return {"LOW": 1, "MED": 2, "HIGH": 3, "CRIT": 4}.get(normalize_severity(value), 1)


def suspicious_weight(event: TimelineEvent) -> int:
    weight = 0
    if event.attack_technique:
        weight += 2
    if normalize_event_type(event.event_type) in {"PERSISTENCE", "INJECTION"}:
        weight += 2
    return weight


def infer_severity(item: Dict[str, Any]) -> str:
    event_type = normalize_event_type(str(item.get("event_type") or item.get("type") or ""))
    if event_type in {"PERSISTENCE", "INJECTION"}:
        return "HIGH"
    if event_type == "NETWORK":
        return "MED"
    return "LOW"


def parse_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_timestamp(value: Any) -> int:
    if isinstance(value, (int, float)):
        number = int(value)
        return number if number > 10_000_000_000 else number * 1000
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return parse_timestamp(int(text))
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return int(datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)
            except ValueError:
                pass
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def format_timestamp(timestamp_ms: int) -> str:
    try:
        return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return str(timestamp_ms)


def event_to_dict(event: TimelineEvent) -> Dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "timestamp_utc": format_timestamp(event.timestamp),
        "event_type": event.event_type,
        "process_name": event.process_name,
        "pid": event.pid,
        "description": event.description,
        "severity": normalize_severity(event.severity),
        "attack_technique": event.attack_technique,
        "raw_data": event.raw_data,
    }


def events_to_markdown(events: List[TimelineEvent]) -> str:
    lines = ["# Selected Timeline Events", ""]
    for event in events:
        lines.extend(
            [
                f"## {format_timestamp(event.timestamp)} - {event.process_name}",
                "",
                f"- Type: {normalize_event_type(event.event_type)}",
                f"- PID: {event.pid}",
                f"- Severity: {normalize_severity(event.severity)}",
                f"- ATT&CK: {event.attack_technique or 'N/A'}",
                f"- Description: {event.description}",
                "",
                "```json",
                json.dumps(event.raw_data, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    return "\n".join(lines)
