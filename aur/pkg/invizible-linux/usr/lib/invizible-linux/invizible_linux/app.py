from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio

from .config import APP_ID
from .oniuxctl import ensure_cargo_path
from .window import MainWindow


class InvizibleApp(Adw.Application):
    def __init__(self, autostart: bool = False) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window: MainWindow | None = None
        self._autostart = autostart
        self._held = False
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)

    def keep_alive(self, on: bool) -> None:
        if on and not self._held:
            self.hold()
            self._held = True
        elif not on and self._held:
            self.release()
            self._held = False

    def do_activate(self) -> None:  # noqa: N802
        if self.window is None:
            self.window = MainWindow(self)
            if self._autostart:
                self.window.schedule_autostart()
        self.window.reveal()


def main() -> int:
    ensure_cargo_path()
    if "--setup" in sys.argv:
        from .distro import setup_system

        return setup_system()
    autostart = "--autostart" in sys.argv
    argv = [a for a in sys.argv if a not in {"--autostart", "--setup"}]
    sys.argv = argv
    app = InvizibleApp(autostart=autostart)
    return app.run(None)
