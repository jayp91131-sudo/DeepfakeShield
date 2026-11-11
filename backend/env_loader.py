import os
import warnings
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DOTENV_PATH = os.path.join(PROJECT_ROOT, ".env")
OBSOLETE_PAYPAL_KEYS = ("PAYPAL_ENV",)

_LAST_DIAGNOSTICS: Optional[Dict[str, Any]] = None


def get_project_dotenv_path() -> str:
    """Returns the canonical project-root .env path."""
    return DEFAULT_DOTENV_PATH


def _parse_dotenv_lines(dotenv_path: str) -> List[Tuple[str, str]]:
    """Parses KEY=VALUE entries from a .env file without mutating os.environ."""
    entries: List[Tuple[str, str]] = []
    with open(dotenv_path, "r", encoding="utf-8-sig") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
                val = val[1:-1]
            if key:
                entries.append((key, val))
    return entries


def inspect_env_file(dotenv_path: Optional[str] = None, apply_to_environ: bool = False) -> Dict[str, Any]:
    """
    Inspects (and optionally loads) the project-root .env file.
    Reports system-environment vs .env conflicts and obsolete PAYPAL_ENV settings
    strictly by key name — NEVER stores, returns, or prints secret values.
    """
    resolved_path = os.path.abspath(dotenv_path) if dotenv_path else DEFAULT_DOTENV_PATH
    exists = os.path.isfile(resolved_path)

    conflicts: List[Dict[str, str]] = []
    obsolete_keys: List[str] = []
    paypal_keys_configured_in_dotenv: List[str] = []
    loaded = False

    for obs_key in OBSOLETE_PAYPAL_KEYS:
        if obs_key in os.environ and os.environ.get(obs_key, "") != "":
            obsolete_keys.append(obs_key)

    if exists:
        try:
            entries = _parse_dotenv_lines(resolved_path)
            for key, val in entries:
                if key in OBSOLETE_PAYPAL_KEYS and val != "" and key not in obsolete_keys:
                    obsolete_keys.append(key)

                if key.startswith("PAYPAL_") and key not in OBSOLETE_PAYPAL_KEYS and val != "":
                    paypal_keys_configured_in_dotenv.append(key)

                if key in os.environ:
                    if val != "" and os.environ.get(key) != val:
                        conflicts.append({
                            "key": key,
                            "resolution": "SYSTEM_ENV_TAKES_PRECEDENCE",
                            "message": f"System environment variable '{key}' overrides project-root .env value."
                        })
                elif apply_to_environ and val != "":
                    os.environ[key] = val
            loaded = True
        except Exception as exc:
            return {
                "dotenv_path": resolved_path,
                "dotenv_exists": exists,
                "dotenv_loaded": False,
                "conflicts": conflicts,
                "obsolete_keys": obsolete_keys,
                "paypal_keys_in_dotenv": paypal_keys_configured_in_dotenv,
                "error": f"Failed to parse .env file ({type(exc).__name__})"
            }

    return {
        "dotenv_path": resolved_path,
        "dotenv_exists": exists,
        "dotenv_loaded": loaded,
        "conflicts": conflicts,
        "obsolete_keys": obsolete_keys,
        "paypal_keys_in_dotenv": paypal_keys_configured_in_dotenv,
        "error": None
    }


def load_env_file(dotenv_path: Optional[str] = None) -> bool:
    """
    Loads the project-root .env file into os.environ for keys not already defined
    by the process/system environment. Emits sanitized warnings (key names only)
    for conflicts or obsolete PAYPAL_ENV settings.
    """
    global _LAST_DIAGNOSTICS
    diag = inspect_env_file(dotenv_path=dotenv_path, apply_to_environ=True)
    _LAST_DIAGNOSTICS = diag

    for conflict in diag.get("conflicts", []):
        warnings.warn(conflict["message"], RuntimeWarning, stacklevel=2)

    if diag.get("obsolete_keys"):
        warnings.warn(
            "Obsolete configuration key(s) detected: "
            + ", ".join(diag["obsolete_keys"])
            + ". Use PAYPAL_PROVIDER_MODE (SANDBOX_API | SIMULATOR) and PAYPAL_BASE_URL instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    return bool(diag.get("dotenv_loaded"))


def get_env_diagnostics(dotenv_path: Optional[str] = None) -> Dict[str, Any]:
    """Returns sanitized, secret-free diagnostics for .env and system environment configuration."""
    return inspect_env_file(dotenv_path=dotenv_path, apply_to_environ=False)
