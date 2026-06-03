"""Plugin system for extensible analysis hooks."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Callable, Optional

from backend.models import AnalysisResult, ParsedConfig
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)

PluginHook = Callable[[AnalysisResult, ParsedConfig], AnalysisResult]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_BUNDLED_PLUGINS = _PROJECT_ROOT / "plugins"


class PluginManager:
    def __init__(self) -> None:
        self._plugins: list[tuple[str, PluginHook]] = []

    def _ensure_user_plugins(self, plugin_dir: Path) -> None:
        """Copy bundled sample plugins to user dir (refresh if bundled is newer)."""
        if not _BUNDLED_PLUGINS.is_dir():
            return
        plugin_dir.mkdir(parents=True, exist_ok=True)
        for src in _BUNDLED_PLUGINS.glob("*.py"):
            if src.name.startswith("_"):
                continue
            dest = plugin_dir / src.name
            if not dest.exists() or src.stat().st_mtime > dest.stat().st_mtime:
                shutil.copy2(src, dest)
                logger.info("Installed/updated sample plugin: %s", src.name)

    def load_plugins(self) -> int:
        settings = get_settings()
        plugin_dir = Path(settings.plugin_dir or Path.home() / ".xray_analyzer" / "plugins")
        self._ensure_user_plugins(plugin_dir)

        search_dirs = [plugin_dir]
        if _BUNDLED_PLUGINS.is_dir():
            search_dirs.append(_BUNDLED_PLUGINS)

        loaded = 0
        seen: set[str] = set()
        for directory in search_dirs:
            for py_file in sorted(directory.glob("*.py")):
                if py_file.name.startswith("_") or py_file.stem in seen:
                    continue
                try:
                    mod_name = f"xray_plugin_{py_file.stem}"
                    spec = importlib.util.spec_from_file_location(mod_name, py_file)
                    if not spec or not spec.loader:
                        continue
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = mod
                    spec.loader.exec_module(mod)
                    hook = getattr(mod, "analyze", None)
                    if callable(hook):
                        self._plugins.append((py_file.stem, hook))
                        seen.add(py_file.stem)
                        loaded += 1
                except Exception as exc:
                    logger.warning("Failed to load plugin %s: %s", py_file.name, exc)
        return loaded

    def run_hooks(self, result: AnalysisResult, config: ParsedConfig) -> AnalysisResult:
        for name, hook in self._plugins:
            try:
                result = hook(result, config)
            except Exception as exc:
                logger.warning("Plugin %s failed: %s", name, exc)
        return result


_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    global _manager
    if _manager is None:
        _manager = PluginManager()
        _manager.load_plugins()
    return _manager
