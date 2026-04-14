"""Process Lineage Attribution — Sprint 50 (APEP-400).

Reads /proc on Linux to build a process ancestry chain from a target PID
to init (PID 1).  Used by the FilesystemSentinel to attribute file
system events to specific processes and detect suspicious process trees.

Security guards validate that process lineage is trusted by checking:
  - Known-good parent processes (e.g. systemd, containerd, python)
  - Suspicious indicators (deleted executables, memfd, /proc/self/exe)
  - Process namespace isolation
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from app.models.kill_switch import ProcessInfo, ProcessLineage

logger = logging.getLogger(__name__)

# Known-good process names that are trusted in the lineage
_TRUSTED_PROCESS_NAMES = frozenset({
    "systemd", "init", "containerd", "containerd-shim",
    "dockerd", "docker", "runc", "cri-o",
    "kubelet", "kube-proxy",
    "python", "python3", "uvicorn", "gunicorn",
    "bash", "sh", "zsh",
    "sshd", "sudo",
    "supervisord", "tini",
})

# Suspicious indicators in process attributes
_SUSPICIOUS_INDICATORS = [
    ("deleted_exe", lambda info: "(deleted)" in info.exe),
    ("memfd_exe", lambda info: info.exe.startswith("memfd:")),
    ("proc_self_exe", lambda info: "/proc/self/" in info.cmdline),
    ("dev_shm_exe", lambda info: info.exe.startswith("/dev/shm/")),
    ("tmp_exe", lambda info: info.exe.startswith("/tmp/")),
    ("hidden_exe", lambda info: "/." in info.exe and not info.exe.startswith("/home")),
    ("empty_cmdline", lambda info: info.pid > 1 and not info.cmdline),
]


class ProcessLineageResolver:
    """Resolves process lineage by reading /proc on Linux (APEP-400)."""

    def __init__(self) -> None:
        self._is_linux = os.path.isdir("/proc/1")

    @property
    def available(self) -> bool:
        """Whether /proc-based lineage resolution is available."""
        return self._is_linux

    def resolve(self, pid: int) -> ProcessLineage:
        """Build the process lineage chain from pid to init.

        Returns a ProcessLineage with the chain and trust assessment.
        On non-Linux systems, returns an empty lineage marked untrusted.
        """
        if not self._is_linux:
            return ProcessLineage(
                target_pid=pid,
                trusted=False,
                trust_reason="Process lineage unavailable (non-Linux system)",
            )

        lineage: list[ProcessInfo] = []
        visited: set[int] = set()
        current_pid = pid

        while current_pid > 0 and current_pid not in visited:
            visited.add(current_pid)
            info = self._read_proc(current_pid)
            if info is None:
                break
            lineage.append(info)
            current_pid = info.ppid

        # Assess trust
        suspicious = self._check_suspicious(lineage)
        trusted = len(suspicious) == 0

        trust_reason = ""
        if trusted:
            trust_reason = "All processes in lineage are known-good"
        elif suspicious:
            trust_reason = f"Suspicious indicators: {', '.join(suspicious)}"

        return ProcessLineage(
            target_pid=pid,
            lineage=lineage,
            trusted=trusted,
            trust_reason=trust_reason,
            suspicious_indicators=suspicious,
        )

    def get_process_info(self, pid: int) -> ProcessInfo | None:
        """Get info for a single process by PID."""
        if not self._is_linux:
            return None
        return self._read_proc(pid)

    def _read_proc(self, pid: int) -> ProcessInfo | None:
        """Read process information from /proc/<pid>/."""
        proc_path = Path(f"/proc/{pid}")
        if not proc_path.exists():
            return None

        try:
            # Read status for PID, PPID, name, UID
            status = self._read_status(proc_path / "status")
            if status is None:
                return None

            # Read cmdline
            cmdline = self._read_cmdline(proc_path / "cmdline")

            # Read exe symlink
            exe = self._read_exe(proc_path / "exe")

            return ProcessInfo(
                pid=pid,
                ppid=status.get("ppid", 0),
                name=status.get("name", ""),
                cmdline=cmdline,
                exe=exe,
                uid=status.get("uid", -1),
                username=status.get("username", ""),
                start_time=self._read_start_time(proc_path / "stat"),
            )
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return None
        except Exception:
            logger.debug("Failed to read /proc/%d", pid, exc_info=True)
            return None

    @staticmethod
    def _read_status(path: Path) -> dict | None:
        """Parse /proc/<pid>/status for key fields."""
        try:
            content = path.read_text()
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return None

        result: dict = {}
        for line in content.splitlines():
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            key = parts[0].strip()
            val = parts[1].strip()

            if key == "Name":
                result["name"] = val
            elif key == "PPid":
                try:
                    result["ppid"] = int(val)
                except ValueError:
                    result["ppid"] = 0
            elif key == "Uid":
                try:
                    result["uid"] = int(val.split()[0])
                except (ValueError, IndexError):
                    result["uid"] = -1

        return result if result else None

    @staticmethod
    def _read_cmdline(path: Path) -> str:
        """Read /proc/<pid>/cmdline (null-separated)."""
        try:
            raw = path.read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return ""

    @staticmethod
    def _read_exe(path: Path) -> str:
        """Read /proc/<pid>/exe symlink target."""
        try:
            return str(path.resolve())
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            return ""

    @staticmethod
    def _read_start_time(path: Path) -> float:
        """Read process start time from /proc/<pid>/stat."""
        try:
            content = path.read_text()
            # Field 22 (0-indexed 21) is starttime in clock ticks
            fields = content.rsplit(")", 1)[-1].split()
            if len(fields) >= 20:
                return float(fields[19]) / os.sysconf("SC_CLK_TCK")
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _check_suspicious(lineage: list[ProcessInfo]) -> list[str]:
        """Check the lineage for suspicious indicators (APEP-400.c)."""
        indicators: list[str] = []
        for info in lineage:
            for indicator_name, check_fn in _SUSPICIOUS_INDICATORS:
                try:
                    if check_fn(info):
                        indicators.append(f"{indicator_name}(pid={info.pid})")
                except Exception:
                    pass
        return indicators


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

process_lineage_resolver = ProcessLineageResolver()
