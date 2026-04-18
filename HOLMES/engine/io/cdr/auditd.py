from __future__ import annotations

from typing import Any

from engine.io.cdr.base import BaseCDRAdapter, normalize_text


class AuditdAdapter(BaseCDRAdapter):
    name = "auditd"

    READ_SYSCALLS = {"open", "openat", "read", "pread64"}
    WRITE_SYSCALLS = {"write", "writev", "pwrite64", "rename", "renameat", "unlink", "unlinkat", "truncate"}
    EXEC_SYSCALLS = {"execve", "execveat"}
    SPAWN_SYSCALLS = {"clone", "fork", "vfork"}
    MAP_MEMORY_SYSCALLS = {"mmap", "mmap2"}
    PROTECT_MEMORY_SYSCALLS = {"mprotect"}
    CONNECT_SYSCALLS = {"connect"}
    ACCEPT_SYSCALLS = {"accept", "accept4"}

    @classmethod
    def can_handle(cls, raw: dict[str, Any]) -> bool:
        logsource = raw.get("logsource")
        if isinstance(logsource, dict):
            if normalize_text(logsource.get("product")) == "linux":
                return True
            if normalize_text(logsource.get("service")) == "auditd":
                return True
        return any(key in raw for key in ("syscall", "exe", "comm", "auditd"))

    def _process_entity(self, raw: dict[str, Any]) -> str | None:
        return self._process_entity_from_ids(
            raw,
            guid_keys=("process_guid",),
            pid_keys=("pid",),
        )

    def _file_entity(self, raw: dict[str, Any]) -> str | None:
        return self._entity("file", raw.get("path") or raw.get("name") or raw.get("cwd"))

    def _ip_entity(self, raw: dict[str, Any]) -> str | None:
        return self._entity("ip", raw.get("addr") or raw.get("remote_addr") or raw.get("dest_ip") or raw.get("saddr"))

    def _memory_entity(self, raw: dict[str, Any]) -> str | None:
        pid = str(raw.get("pid") or "").strip()
        addr = str(raw.get("addr") or raw.get("memory_addr") or raw.get("vm_start") or raw.get("start") or "").strip()
        if not addr:
            return None
        if pid:
            return f"mem:{pid}:{addr}:0"
        return f"mem:{addr}:0"

    @staticmethod
    def _has_exec_protection(raw: dict[str, Any]) -> bool:
        for key in ("prot", "protection", "flags", "a2", "a3", "argv", "args"):
            value = raw.get(key)
            if isinstance(value, list):
                haystack = " ".join(str(item) for item in value)
            else:
                haystack = str(value or "")
            if "prot_exec" in haystack.lower():
                return True
        return False

    def to_cdr(self, raw: dict[str, Any]) -> dict[str, Any]:
        syscall = normalize_text(raw.get("syscall") or raw.get("event_type") or raw.get("type"))
        subject = self._process_entity(raw)
        object_: str | None = None
        relations: list[dict[str, str]] = []

        def add(rel: str, src: str | None, dst: str | None) -> None:
            if src and dst:
                relations.append({"relation": rel, "src": src, "dst": dst})

        if syscall in self.EXEC_SYSCALLS:
            object_ = self._process_entity_from_ids(
                {
                    "process_guid": raw.get("child_guid"),
                    "pid": raw.get("child_pid"),
                    "ts": raw.get("ts") or raw.get("timestamp"),
                },
                guid_keys=("process_guid",),
                pid_keys=("pid",),
            ) or self._entity("file", raw.get("path") or raw.get("exe"))
            add("execute", subject, object_)
        elif syscall in self.SPAWN_SYSCALLS:
            object_ = self._process_entity_from_ids(
                {
                    "process_guid": raw.get("child_guid"),
                    "pid": raw.get("child_pid"),
                    "ts": raw.get("ts") or raw.get("timestamp"),
                },
                guid_keys=("process_guid",),
                pid_keys=("pid",),
            )
            add("spawn", subject, object_)
        elif syscall in self.CONNECT_SYSCALLS:
            object_ = self._ip_entity(raw)
            add("connect", subject, object_)
        elif syscall in self.ACCEPT_SYSCALLS:
            object_ = self._ip_entity(raw)
            add("accept", subject, object_)
        elif syscall in self.MAP_MEMORY_SYSCALLS:
            object_ = self._memory_entity(raw)
            if self._has_exec_protection(raw):
                add("make_mem_exec", subject, object_)
        elif syscall in self.PROTECT_MEMORY_SYSCALLS:
            object_ = self._memory_entity(raw)
            if self._has_exec_protection(raw):
                add("protect_memory_exec", subject, object_)
        else:
            object_ = self._file_entity(raw)
            if syscall in self.READ_SYSCALLS:
                add("read", subject, object_)
            elif syscall in self.WRITE_SYSCALLS:
                add("write", subject, object_)

        event_type = raw.get("event_type")
        if event_type is None:
            mapped = dict(raw)
            mapped["event_type"] = syscall or "auditd_event"
            raw = mapped
        cdr = dict(raw.get("cdr", {})) if isinstance(raw.get("cdr"), dict) else {}
        if raw.get("euid") is not None:
            try:
                euid = int(str(raw.get("euid")).strip())
            except ValueError:
                euid = None
            if euid is not None:
                cdr["privilege"] = {"euid": euid}
                raw = dict(raw)
                raw["cdr"] = cdr

        return self._finalize(
            raw,
            subject=subject,
            object_=object_,
            semantic_relations=relations,
            source_type="linux/auditd",
            logsource={"product": "linux", "service": "auditd"},
        )
