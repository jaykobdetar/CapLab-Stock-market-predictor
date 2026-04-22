#!/usr/bin/env python3
"""Live stock-market predictor — friendly names + cross-platform wrapper.

This is a thin wrapper around :mod:`caplab_sim.live_monitor` that adds two
conveniences on top of the package-level module:

1.  **Friendly group labels.**  The raw monitor renders each conglomerate
    as ``g{recno}``.  This wrapper resolves ``recno`` to a human-readable
    name via a JSON mapping (``predictor_names.json`` by default, or a
    path passed with ``--names``).  Unmapped recnos fall back to
    ``g{recno}`` so nothing disappears.

2.  **Windows support.**  The underlying :mod:`caplab_sim.rng_reader`
    uses ``/proc/<pid>/mem`` for all memory access, which is Linux-only.
    When this script is run on Windows it patches the four low-level
    helpers (``_find_capmain_pid``, ``_find_capmain_base``, ``_read_mem``,
    ``_iter_rw_ranges``) with ctypes implementations that call
    ``OpenProcess`` / ``ReadProcessMemory`` / ``EnumProcessModules`` /
    ``VirtualQueryEx``.  CapMain.exe running natively on Windows is then
    accessible without Wine.

Usage
-----
::

    # Linux (Wine) or Windows (native).  Default: rich TUI, 0.1 s poll.
    python predictor.py

    # Custom name mapping (relative or absolute path).
    python predictor.py --names my_names.json

    # Dump candidate ASCII strings from each live Group to help populate
    # the JSON file.  Does not enter the monitor loop.
    python predictor.py --scan-names

    # All flags from caplab_sim.live_monitor are accepted and forwarded.
    python predictor.py --poll 0.05 --log run.jsonl --no-tui

Name discovery
--------------
Names are auto-populated from live memory on attach.  Each Group stores
its conglomerate name as a null-terminated ASCII string at
**Group+0x0008** (long form, up to 20 bytes) and **Group+0x0047** (short
form, up to ~12 bytes).  Both were confirmed against v11.1.2 via the
``--scan-names`` helper — see ``SESSION_LOG.txt`` (2026-04-22f) for the
offset-pinning story.

Zero-config labels work out of the box — you don't need a names file.
A JSON file remains supported as an override (e.g., rename "Player Corp"
to "You", or substitute a more colourful tag for an AI you've come to
loathe).  JSON entries win over live-memory names on a per-recno basis::

    {
      "2": "You",
      "3": "Enemy #1"
    }

Keys may be strings or integers.  Use ``--short-names`` to pull from
Group+0x47 instead of Group+0x08 when terminal width is tight.

Windows notes
-------------
*   The script must run with the same user the game runs as (or with
    higher privileges — ``PROCESS_VM_READ | PROCESS_QUERY_INFORMATION``
    require it).
*   The scan for the Misc pointer walks up to 3 MB of CapMain.exe's
    .text section — this is the same heuristic the Linux reader uses,
    so behaviour matches byte-for-byte once the ctypes patches are
    installed.
*   Only 32-bit CapMain.exe is supported (the game is 32-bit).  The
    Python interpreter itself may be 32- or 64-bit; ``ReadProcessMemory``
    handles the WOW64 bridge transparently.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# Add the directory containing this script to sys.path so we can import
# caplab_sim without needing `pip install -e .`.  The script lives one
# level above the caplab_sim package by design (user request: "sit in the
# folder above caplab_sim").
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


# ---------------------------------------------------------------------------
# Group name resolver
# ---------------------------------------------------------------------------

# The module-level mapping the monkey-patched render methods consult.
# Populated by :func:`load_names`; callers can also assign directly for
# programmatic use.
NAMES: Dict[int, str] = {}


def load_names(path: Optional[str]) -> Dict[int, str]:
    """Load a ``recno -> name`` mapping from a JSON file.

    Returns an empty dict (NOT an error) when ``path`` is None and the
    default ``predictor_names.json`` file is also absent.  That makes the
    zero-config case "just work" — labels degrade to ``g{recno}``.

    Keys in the JSON may be strings (``"2"``) or integers; both are
    accepted and normalised to ``int`` in the returned dict.  Non-numeric
    keys are silently skipped so a stray comment field doesn't crash
    startup.
    """
    # Path precedence: CLI argument > default beside this script.
    if path is None:
        default_path = _HERE / "predictor_names.json"
        if default_path.exists():
            path = str(default_path)
        else:
            return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"predictor: names file not found: {path}", file=sys.stderr)
        return {}
    except json.JSONDecodeError as exc:
        print(
            f"predictor: failed to parse {path}: {exc}.  "
            f"Falling back to g{{recno}} labels.",
            file=sys.stderr,
        )
        return {}

    out: Dict[int, str] = {}
    if not isinstance(raw, dict):
        print(
            f"predictor: {path} must contain a JSON object "
            f"(got {type(raw).__name__}).  Falling back to g{{recno}} labels.",
            file=sys.stderr,
        )
        return {}
    for k, v in raw.items():
        try:
            recno = int(k)
        except (TypeError, ValueError):
            continue
        if isinstance(v, str) and v:
            out[recno] = v
    return out


def label_for(recno: int) -> str:
    """Return the display label for ``recno``.

    Wrapped-monitor render paths call this once per row per frame.  The
    lookup is a single dict access + fallback — cheap enough to run at
    every poll.
    """
    name = NAMES.get(recno)
    return name if name is not None else f"g{recno}"


# ---------------------------------------------------------------------------
# Live-memory name discovery (Group+0x08 / Group+0x47)
# ---------------------------------------------------------------------------

# Offsets found via --scan-names against Capitalism Lab v11.1.2 on
# 2026-04-22.  Each Group stores two null-terminated ASCII names back-to-
# back: the long form at +0x08 (display / UI label) and an abbreviated
# form at +0x47 (used in compact views).  Both are recorded in the
# SESSION_LOG entry for the same date.
GROUP_NAME_OFFSET_LONG: int = 0x08
GROUP_NAME_OFFSET_SHORT: int = 0x47
# Generous upper bound on how many bytes to read.  The short name slot
# ends well before +0x70 (nation_ptr), so 0x40 bytes is plenty and
# safely under the GROUP_NATION_STOCK_PTR_OFFSET in rng_reader.
GROUP_NAME_MAX_LEN: int = 0x40


def _decode_c_string(blob: bytes, max_len: int = GROUP_NAME_MAX_LEN) -> str:
    """Decode a null-terminated ASCII string from ``blob``.

    Stops at the first NUL byte, or at ``max_len``, whichever comes
    first.  Non-printable bytes (anything outside 0x20..0x7E) are also
    treated as terminators so a stray high-bit byte doesn't leak
    binary garbage into the UI.  Returns the empty string on any
    failure so the caller can fall back to ``g{recno}`` cleanly.
    """
    out: List[int] = []
    for i in range(min(len(blob), max_len)):
        b = blob[i]
        if b == 0 or not (0x20 <= b <= 0x7E):
            break
        out.append(b)
    return bytes(out).decode("ascii", errors="replace")


def discover_names_from_memory(
    reader, *, use_short: bool = False,
) -> Dict[int, str]:
    """Walk every live Group and read its name string from memory.

    Returns a ``{recno: name}`` dict.  The ``reader`` argument is a live
    :class:`caplab_sim.rng_reader.LiveGameReader` — it must be attached
    to a running CapMain.exe before calling this function.

    ``use_short=True`` pulls the abbreviated Group+0x47 label (roughly
    12 chars) instead of the full Group+0x08 label (up to 20 chars).
    Useful when the TUI has many columns and horizontal real estate is
    tight.

    Groups whose name read fails (OSError, empty string, pure
    whitespace) are omitted — :func:`label_for` will fall back to
    ``g{recno}`` for those, which is the right degrade.
    """
    from caplab_sim.rng_reader import _read_mem

    offset = GROUP_NAME_OFFSET_SHORT if use_short else GROUP_NAME_OFFSET_LONG

    names: Dict[int, str] = {}
    for _tag, slot, group_ptr in reader.iter_groups():
        try:
            blob = _read_mem(reader.pid, group_ptr + offset,
                             GROUP_NAME_MAX_LEN)
        except OSError:
            continue
        name = _decode_c_string(blob)
        # Some slots (e.g. Government, or empty placeholders) carry a
        # name but aren't "real" groups for the monitor's purposes.  The
        # monitor filters by listed/domestic anyway, so we include every
        # non-empty name here and let the renderer skip rows whose
        # stock isn't listed.  A completely empty field is dropped so
        # label_for returns g{recno} rather than a blank cell.
        if name.strip():
            names[slot] = name
    return names


# ---------------------------------------------------------------------------
# Windows memory-reading shim
# ---------------------------------------------------------------------------

def _install_windows_patches() -> None:
    """Monkey-patch :mod:`caplab_sim.rng_reader` for Windows.

    Replaces the four Linux-specific helpers (``_find_capmain_pid``,
    ``_find_capmain_base``, ``_read_mem``, ``_iter_rw_ranges``) with
    ctypes-backed implementations that use the Win32 process API.

    Idempotent — calling it twice is a no-op on the second call (the
    helpers check a sentinel attribute on the module).

    No-op on non-Windows platforms: the Linux /proc code is the default
    and this function returns without touching the module.
    """
    if sys.platform != "win32":
        return

    import ctypes
    import ctypes.wintypes as wt

    from caplab_sim import rng_reader

    # Idempotency guard.  `_predictor_win_patched` is set to True on the
    # first successful install and checked on subsequent calls.
    if getattr(rng_reader, "_predictor_win_patched", False):
        return

    # -- Win32 constants & function prototypes -----------------------------

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    PROCESS_ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

    MEM_COMMIT = 0x1000
    PAGE_READABLE_MASK = 0x66   # R | RW | WCX | RCX — accepts any 'r' flavour
    # (PAGE_READONLY=0x02, PAGE_READWRITE=0x04, PAGE_WRITECOPY=0x08,
    #  PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40,
    #  PAGE_EXECUTE_WRITECOPY=0x80 — we want everything with a readable
    #  bit; mask 0x66 hits RO/RW/ER/ERW.  For safety we also check
    #  PAGE_WRITECOPY and PAGE_EXECUTE_WRITECOPY separately below.)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    # MEMORY_BASIC_INFORMATION (32-bit layout used by VirtualQueryEx on
    # a 32-bit target; the Python side is wt-sized so this works
    # regardless of the Python bitness because we use BaseAddress / etc
    # fields directly).
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", wt.DWORD),
            ("EntryPoint", ctypes.c_void_p),
        ]

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    OpenProcess.restype = wt.HANDLE

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wt.HANDLE]
    CloseHandle.restype = wt.BOOL

    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    ReadProcessMemory.restype = wt.BOOL

    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [
        wt.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    VirtualQueryEx.restype = ctypes.c_size_t

    EnumProcesses = psapi.EnumProcesses
    EnumProcesses.argtypes = [
        ctypes.POINTER(wt.DWORD), wt.DWORD, ctypes.POINTER(wt.DWORD),
    ]
    EnumProcesses.restype = wt.BOOL

    EnumProcessModules = psapi.EnumProcessModules
    EnumProcessModules.argtypes = [
        wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD,
        ctypes.POINTER(wt.DWORD),
    ]
    EnumProcessModules.restype = wt.BOOL

    GetModuleBaseNameW = psapi.GetModuleBaseNameW
    GetModuleBaseNameW.argtypes = [
        wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD,
    ]
    GetModuleBaseNameW.restype = wt.DWORD

    GetModuleInformation = psapi.GetModuleInformation
    GetModuleInformation.argtypes = [
        wt.HANDLE, wt.HMODULE, ctypes.POINTER(MODULEINFO), wt.DWORD,
    ]
    GetModuleInformation.restype = wt.BOOL

    # -- helper: cached process-handle per pid -----------------------------
    #
    # Opening a handle on every _read_mem call is ~0.1 ms overhead — fine
    # for low-frequency reads, but _iter_group_pointers issues O(n_groups)
    # reads per snapshot and a 0.5 ms * 30 groups = 15 ms penalty per poll
    # adds up at speed 15.  Cache the handle keyed by pid; invalidate if
    # a read fails (process exited / handle closed).

    _handle_cache: Dict[int, int] = {}

    def _get_handle(pid: int) -> Optional[int]:
        h = _handle_cache.get(pid)
        if h is not None:
            return h
        h_new = OpenProcess(PROCESS_ACCESS, False, pid)
        if not h_new:
            return None
        _handle_cache[pid] = h_new
        return h_new

    def _drop_handle(pid: int) -> None:
        h = _handle_cache.pop(pid, None)
        if h is not None:
            CloseHandle(h)

    # -- patched helpers ---------------------------------------------------

    def _win_find_capmain_pid() -> Optional[int]:
        """Return the PID of CapMain.exe, scanning all processes."""
        # 4096 DWORDs = up to 4096 pids.  Doubled to 8192 on overflow.
        n = 4096
        while True:
            arr_type = wt.DWORD * n
            pids = arr_type()
            needed = wt.DWORD(0)
            if not EnumProcesses(pids, ctypes.sizeof(pids),
                                 ctypes.byref(needed)):
                return None
            count = needed.value // ctypes.sizeof(wt.DWORD)
            if count < n:
                break
            n *= 2
            if n > 1 << 20:
                # Something is very wrong; 1M pids is impossible.
                return None

        for i in range(count):
            pid = pids[i]
            if pid == 0:
                continue
            h = OpenProcess(PROCESS_ACCESS, False, pid)
            if not h:
                continue
            try:
                mods = (wt.HMODULE * 1)()
                cb_needed = wt.DWORD(0)
                if not EnumProcessModules(h, mods, ctypes.sizeof(mods),
                                          ctypes.byref(cb_needed)):
                    continue
                buf = ctypes.create_unicode_buffer(260)
                GetModuleBaseNameW(h, mods[0], buf, 260)
                if "CapMain" in buf.value:
                    # Don't close the handle — we'll reuse it for reads.
                    _handle_cache[pid] = h
                    return pid
            finally:
                if _handle_cache.get(pid) is None:
                    CloseHandle(h)
        return None

    def _win_find_capmain_base(pid: int) -> Optional[int]:
        """Return the CapMain.exe module base for ``pid``."""
        h = _get_handle(pid)
        if h is None:
            return None
        # EnumProcessModules: sized-try-then-resize dance.
        cb_needed = wt.DWORD(0)
        # First call with a 4-entry buffer to query required size.
        dummy = (wt.HMODULE * 4)()
        if not EnumProcessModules(h, dummy, ctypes.sizeof(dummy),
                                  ctypes.byref(cb_needed)):
            return None
        n_mods = max(cb_needed.value // ctypes.sizeof(wt.HMODULE), 1)
        mods = (wt.HMODULE * n_mods)()
        if not EnumProcessModules(h, mods, ctypes.sizeof(mods),
                                  ctypes.byref(cb_needed)):
            return None
        buf = ctypes.create_unicode_buffer(260)
        for i in range(n_mods):
            if not mods[i]:
                continue
            GetModuleBaseNameW(h, mods[i], buf, 260)
            if "CapMain" in buf.value:
                info = MODULEINFO()
                if GetModuleInformation(h, mods[i], ctypes.byref(info),
                                        ctypes.sizeof(info)):
                    return info.lpBaseOfDll or 0
        return None

    def _win_read_mem(pid: int, address: int, size: int) -> bytes:
        """Read ``size`` bytes from the target process via ReadProcessMemory.

        Raises ``OSError`` on any failure to match the Linux reader's
        contract — the caller treats OSError as "unmapped / exited".
        """
        h = _get_handle(pid)
        if h is None:
            raise OSError("could not open target process")
        buf = (ctypes.c_ubyte * size)()
        bytes_read = ctypes.c_size_t(0)
        ok = ReadProcessMemory(h, ctypes.c_void_p(address), buf, size,
                               ctypes.byref(bytes_read))
        if not ok or bytes_read.value == 0:
            # Invalidate the handle on failure so the next read tries
            # to re-open (catches post-exit transitions quickly).
            err = ctypes.get_last_error()
            _drop_handle(pid)
            raise OSError(
                f"ReadProcessMemory @ 0x{address:08x} size={size} failed "
                f"(err={err})"
            )
        return bytes(buf[:bytes_read.value])

    def _win_iter_rw_ranges(pid: int):
        """Yield ``(start, end)`` for every readable mapping in the target.

        Mirrors the Linux ``/proc/pid/maps`` helper: walks
        VirtualQueryEx page by page, coalescing contiguous readable
        regions that share the same AllocationBase.
        """
        h = _get_handle(pid)
        if h is None:
            return
        addr = 0
        # User-mode VA space on 32-bit Windows tops out at 0x80000000
        # (2 GB) or 0xC0000000 with /LARGEADDRESSAWARE; 0x80000000 is
        # a safe upper bound for CapMain.exe.
        END_VA = 0x80000000
        while addr < END_VA:
            mbi = MEMORY_BASIC_INFORMATION()
            ret = VirtualQueryEx(h, ctypes.c_void_p(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
            if ret == 0:
                break
            region_base = mbi.BaseAddress or 0
            region_end = region_base + mbi.RegionSize
            if mbi.State == MEM_COMMIT:
                prot = mbi.Protect
                # Any "readable" protection bit.  PAGE_NOACCESS=0x01 and
                # PAGE_GUARD=0x100 are excluded.
                if prot and not (prot & 0x101):
                    yield region_base, region_end
            # Step to the next region.  RegionSize is the length of
            # this span; guard against zero-advance on unexpected values.
            if mbi.RegionSize == 0:
                break
            addr = region_end

    # -- install ---------------------------------------------------------

    rng_reader._find_capmain_pid = _win_find_capmain_pid
    rng_reader._find_capmain_base = _win_find_capmain_base
    rng_reader._read_mem = _win_read_mem
    rng_reader._iter_rw_ranges = _win_iter_rw_ranges
    rng_reader._predictor_win_patched = True


# ---------------------------------------------------------------------------
# Label-aware monkey patches for live_monitor's render paths
# ---------------------------------------------------------------------------

def _install_label_patches() -> None:
    """Replace Renderer._render_tui / _render_plain so labels use names.

    The two methods are copy-pasted from ``caplab_sim.live_monitor`` with
    the three ``f"g{recno...}"`` formatting sites replaced by
    :func:`label_for`.  Keeping the copies here rather than reaching into
    the string-template surface of the original module avoids an
    introspection-based monkey-patch and keeps the logic easy to read.

    The end-of-run summary formatter (``print(f"  g{recno:>3d}: ...")``
    inside ``run()``) is also patched indirectly by substituting a
    ``run()`` wrapper — see :func:`_patch_run`.
    """
    from caplab_sim import live_monitor as lm

    # -- patched _render_tui ------------------------------------------------

    def _render_tui_named(
        self, reader, last, stats, last_transition, status,
    ):
        from rich.console import Group as RichGroup
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        header_lines = [
            f"pid={reader.pid}  base=0x{reader.base:08x}  "
            f"misc=0x{reader.misc_addr:08x}",
        ]
        if last is not None:
            header_lines.append(
                f"seed=0x{last.seed:08x}  "
                f"listed-domestic={len(last.listed_recnos)}  "
                f"status={status}"
            )
        else:
            header_lines.append(f"status={status}")

        if last_transition is not None:
            d = last_transition
            ia_s = "sim" if d.best_inter_advance == -1 else str(d.best_inter_advance)
            header_lines.append(
                f"last transition: k={d.best_k} ia={ia_s} "
                f"stock_rng_calls={d.best_rng_calls} "
                f"{d.n_matched}/{d.n_total} match "
                f"seed_distance={d.seed_distance}"
            )

        ia_hist = dict(sorted(stats.inter_advance_histogram.items()))
        vector_days = ia_hist.pop(-1, 0)
        ia_mode = (f"sim={vector_days}d" if vector_days else
                   f"scalar={ia_hist}")
        header_lines.append(
            f"cumulative: transitions={stats.transitions}  "
            f"matched={stats.total_matched}/{stats.total_observed} "
            f"({stats.fraction:.1%})  "
            f"k_hist={dict(sorted(stats.k_histogram.items()))}  "
            f"ia={ia_mode}"
        )
        header = Text("\n".join(header_lines))

        # New simplified layout: 5 columns.
        #   Group | Price (now → next Δ) | Sentiment (now → next Δ)
        #     | Match (last transition) | Hits (cumulative).
        #
        # Price and Sentiment cells each bundle "current value", "predicted
        # next value", and the forward delta (next − now).  Arrows and
        # deltas are coloured: green for positive, red for negative, dim
        # grey for near-zero.  "Match" is green OK / red MISS / dim "—";
        # row style stays unstyled so the cell colours read cleanly.
        table = Table(show_header=True, header_style="bold",
                      title="Live stock monitor", title_style="bold",
                      expand=True, pad_edge=False)
        table.add_column("Group", justify="left", style="bold")
        table.add_column("Price  (now  →  next  Δ)", justify="right")
        table.add_column("Sentiment  (now  →  next  Δ)", justify="right")
        table.add_column("Match", justify="center")
        table.add_column("Hits", justify="right", style="dim")

        per_recno_diff = {}
        if last_transition is not None:
            per_recno_diff = {d.group_recno: d for d in last_transition.diffs}

        def _delta_style(delta: float, eps: float) -> str:
            if delta > eps:
                return "green"
            if delta < -eps:
                return "red"
            return "dim"

        def _fmt_price_cell(now_val: float, pred) -> Text:
            t = Text()
            t.append(f"{now_val:7.4f}")
            if pred is None:
                t.append("  →  ", style="dim")
                t.append(f"{'—':>7}", style="dim")
                t.append(f"   {'—':>8}", style="dim")
                return t
            nxt = pred.base_stock_price
            delta = nxt - now_val
            style = _delta_style(delta, 1e-5)
            t.append("  →  ", style="dim")
            t.append(f"{nxt:7.4f}", style=style)
            t.append(f"   {delta:+8.4f}", style=style)
            return t

        def _fmt_sent_cell(now_val: float, pred) -> Text:
            t = Text()
            t.append(f"{now_val:+7.2f}")
            if pred is None:
                t.append("  →  ", style="dim")
                t.append(f"{'—':>7}", style="dim")
                t.append(f"   {'—':>7}", style="dim")
                return t
            nxt = pred.sentiment
            delta = nxt - now_val
            style = _delta_style(delta, 1e-3)
            t.append("  →  ", style="dim")
            t.append(f"{nxt:+7.2f}", style=style)
            t.append(f"   {delta:+7.2f}", style=style)
            return t

        def _fmt_match_cell(td) -> Text:
            if td is None:
                return Text("—", style="dim")
            if td.matches:
                return Text("OK", style="bold green")
            return Text("MISS", style="bold red")

        if last is not None:
            forecast_by_recno = {p.group_recno: p for p in last.forecast.per_stock}
            for recno in last.listed_recnos:
                s = next(
                    (x for x in last.inputs if x.group_recno == recno), None
                )
                if s is None:
                    continue
                pred = forecast_by_recno.get(recno)
                td = per_recno_diff.get(recno)
                pg = stats.per_group.get(recno)
                if pg and pg[1]:
                    hr_s = f"{pg[0]}/{pg[1]}"
                else:
                    hr_s = "—"
                table.add_row(
                    label_for(recno),
                    _fmt_price_cell(s.base_stock_price, pred),
                    _fmt_sent_cell(s.sentiment, pred),
                    _fmt_match_cell(td),
                    hr_s,
                )

        assert self._live is not None
        self._live.update(
            RichGroup(
                Panel(header, border_style="cyan", expand=True),
                table,
            ),
            refresh=True,
        )

    # -- patched _render_plain ----------------------------------------------

    def _render_plain_named(
        self, reader, last, stats, last_transition, status,
    ):
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[2J\x1b[H")

        print(
            f"pid={reader.pid} base=0x{reader.base:08x} "
            f"misc=0x{reader.misc_addr:08x}  status={status}"
        )
        if last is not None:
            print(
                f"seed=0x{last.seed:08x}  listed-domestic={len(last.listed_recnos)}"
            )
        if last_transition is not None:
            d = last_transition
            ia_s = "sim" if d.best_inter_advance == -1 else str(d.best_inter_advance)
            print(
                f"last transition: k={d.best_k} ia={ia_s} "
                f"stock_rng_calls={d.best_rng_calls} "
                f"{d.n_matched}/{d.n_total} match seed_distance={d.seed_distance}"
            )
        ia_hist_display = dict(sorted(stats.inter_advance_histogram.items()))
        ia_vec_d = ia_hist_display.pop(-1, 0)
        ia_mode = (f"sim={ia_vec_d}d" if ia_vec_d else
                   f"scalar={ia_hist_display}")
        print(
            f"cumulative: transitions={stats.transitions}  "
            f"matched={stats.total_matched}/{stats.total_observed} "
            f"({stats.fraction:.1%})  "
            f"k_hist={dict(sorted(stats.k_histogram.items()))}  "
            f"ia={ia_mode}"
        )

        if last is None:
            return

        per_recno_diff = {}
        if last_transition is not None:
            per_recno_diff = {d.group_recno: d for d in last_transition.diffs}
        forecast_by_recno = {p.group_recno: p for p in last.forecast.per_stock}

        # Column width for the group label — widest label in the current
        # snapshot, floor of 6 so single-letter names don't collapse.
        label_w = max(
            (len(label_for(r)) for r in last.listed_recnos), default=6
        )
        label_w = max(label_w, 6)

        # New simplified layout — group | price (now → next Δ)
        # | sentiment (now → next Δ) | match.  Each bundle reads left to
        # right: current value, an arrow, the predicted next value, then
        # the forward delta (next − now).  The subheader below uses the
        # exact same field widths as the data rows so columns line up.
        price_hdr = f"{'now':>7}  →  {'next':>7}   {'Δ':>8}"
        sent_hdr = f"{'now':>7}  →  {'next':>7}   {'Δ':>7}"
        price_block_w = len(price_hdr)
        sent_block_w = len(sent_hdr)

        print(
            f"\n{'group':<{label_w}}  "
            f"{'price':^{price_block_w}}  "
            f"{'sentiment':^{sent_block_w}}  match"
        )
        print(
            f"{'':<{label_w}}  "
            f"{price_hdr}  "
            f"{sent_hdr}"
        )
        print("-" * (label_w + price_block_w + sent_block_w + 12))
        for recno in last.listed_recnos:
            s = next((x for x in last.inputs if x.group_recno == recno), None)
            if s is None:
                continue
            pred = forecast_by_recno.get(recno)
            if pred is None:
                p_next_s = f"{'—':>7}"
                p_delta_s = f"{'—':>8}"
                s_next_s = f"{'—':>7}"
                s_delta_s = f"{'—':>7}"
            else:
                p_next_s = f"{pred.base_stock_price:7.4f}"
                p_delta_s = f"{pred.base_stock_price - s.base_stock_price:+8.4f}"
                s_next_s = f"{pred.sentiment:+7.2f}"
                s_delta_s = f"{pred.sentiment - s.sentiment:+7.2f}"
            td = per_recno_diff.get(recno)
            m = "—" if td is None else ("OK" if td.matches else "MISS")
            lbl = label_for(recno)
            print(
                f"{lbl:<{label_w}}  "
                f"{s.base_stock_price:7.4f}  →  {p_next_s}   {p_delta_s}  "
                f"{s.sentiment:+7.2f}  →  {s_next_s}   {s_delta_s}  "
                f"{m}"
            )

    lm.Renderer._render_tui = _render_tui_named
    lm.Renderer._render_plain = _render_plain_named


def _patch_run() -> None:
    """Wrap ``live_monitor.run`` so the end-of-run summary uses names.

    The summary block inside ``run()`` prints ``f"  g{recno:>3d}: ..."``.
    Rather than re-implement the whole 100-line run loop we route the
    call through the original function and post-process nothing — the
    summary text is already sent to stdout line-by-line, so we can't
    intercept it without subclassing.  Instead, wrap the full function
    and print a second, name-aware summary after it returns.  We keep
    the original summary too because it doubles as a legacy log format.
    """
    from caplab_sim import live_monitor as lm

    _original_run = lm.run

    def _run_named(cfg) -> int:
        # Reach into the original module to copy the running-stats into
        # a local we can render after the fact.  `run` doesn't return
        # the stats object, so we intercept via a patched
        # `RunningStats.ingest` that remembers every transition's
        # per-group counters against the monkey-patched attribute.
        #
        # Simpler approach: capture via a thread-local "last stats ref".
        # Cleanest: replace the whole RunningStats class with a subclass
        # that registers itself on __init__.

        captured: List[lm.RunningStats] = []
        _OrigStats = lm.RunningStats

        class _NamedStats(_OrigStats):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                captured.append(self)

        lm.RunningStats = _NamedStats
        try:
            rc = _original_run(cfg)
        finally:
            lm.RunningStats = _OrigStats

        if captured:
            stats = captured[0]
            if stats.per_group:
                # Width of the widest label for alignment.  Floor of 6
                # so short names don't cause layout jitter.
                label_w = max(
                    (len(label_for(r)) for r in stats.per_group.keys()),
                    default=6,
                )
                label_w = max(label_w, 6)
                print("\n--- per-group hit rates (named; worst first) ---")
                rows = []
                for recno, (hit, total) in stats.per_group.items():
                    rate = hit / total if total else 0.0
                    rows.append((rate, recno, hit, total))
                for rate, recno, hit, total in sorted(rows):
                    lbl = label_for(recno)
                    print(
                        f"  {lbl:<{label_w}}: {hit}/{total} ({rate:.1%})"
                    )
        return rc

    lm.run = _run_named


# ---------------------------------------------------------------------------
# --scan-names helper: dump ASCII runs from each live Group's memory
# ---------------------------------------------------------------------------

def _scan_ascii_runs(blob: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Return ``(offset, string)`` for every printable ASCII run in ``blob``.

    A "run" is a sequence of bytes in the printable ASCII range
    (0x20..0x7E) of length >= ``min_len``, terminated by any non-printable
    byte (including NUL).  Offsets are relative to ``blob[0]``.  Useful
    for hunting down the group-name field inside a Group struct whose
    layout hasn't been fully reverse-engineered.
    """
    out: List[Tuple[int, str]] = []
    n = len(blob)
    i = 0
    while i < n:
        if 0x20 <= blob[i] <= 0x7E:
            j = i
            while j < n and 0x20 <= blob[j] <= 0x7E:
                j += 1
            if j - i >= min_len:
                out.append((i, blob[i:j].decode("ascii")))
            i = j + 1
        else:
            i += 1
    return out


def _run_scan_names(min_len: int = 4) -> int:
    """Connect to the game and dump ASCII runs from each live Group.

    Prints one block per group with (offset, string) pairs.  Use the
    output to identify which offset holds the conglomerate name, then
    drop a ``predictor_names.json`` file next to the script mapping
    ``recno -> name``.  Does not start the monitor loop — scan-and-exit.
    """
    from caplab_sim.rng_reader import (
        LiveGameReader, _read_mem, GROUP_NATION_STOCK_PTR_OFFSET,
    )

    try:
        reader = LiveGameReader.attach()
    except RuntimeError as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        return 2

    # Group struct is 0x4A18 bytes in the save file (inlined) — same size
    # in live memory; dump the whole thing so the user can spot the name
    # regardless of which offset holds it.
    GROUP_BLOB_SIZE = 0x4A18

    print(f"predictor: scanning live Groups for ASCII strings "
          f"(min_len={min_len})")
    print(f"predictor: pid={reader.pid} base=0x{reader.base:08x}")

    for tag, slot, group_ptr in reader.iter_groups():
        try:
            blob = _read_mem(reader.pid, group_ptr, GROUP_BLOB_SIZE)
        except OSError as exc:
            print(f"\n[{tag}] slot={slot} (read error: {exc})")
            continue
        runs = _scan_ascii_runs(blob, min_len=min_len)
        # Filter out the trivially-meaningless runs: single-character
        # repetitions and all-digit strings rarely carry names.  Keep the
        # rest ranked by length (longest = most likely to be the name).
        interesting = [
            (off, s) for off, s in runs
            if len(set(s)) > 1 and not s.isdigit()
        ]
        interesting.sort(key=lambda os_: -len(os_[1]))
        print(f"\n[{tag}] slot={slot} group_ptr=0x{group_ptr:08x}")
        if not interesting:
            print("  (no ASCII runs matching filters)")
            continue
        # Top 8 is usually enough — the conglomerate name typically
        # dominates because most other struct fields are numeric.
        for off, s in interesting[:8]:
            print(f"  +0x{off:04x}  {s!r}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> Tuple[argparse.Namespace, List[str]]:
    """Parse our wrapper flags; remaining args are forwarded to live_monitor."""
    p = argparse.ArgumentParser(
        prog="predictor.py",
        description=(
            "Wrapper around caplab_sim.live_monitor with friendly group "
            "labels and cross-platform memory reading."
        ),
    )
    p.add_argument(
        "--names", type=str, default=None, metavar="PATH",
        help=(
            "JSON file mapping group-recno (string or int key) -> "
            "display name.  Default: predictor_names.json beside this "
            "script, if present; otherwise labels fall back to "
            "g{recno}."
        ),
    )
    p.add_argument(
        "--scan-names", action="store_true",
        help=(
            "Dump ASCII strings found in each live Group's memory so "
            "you can identify the conglomerate name offset, then exit.  "
            "Does not run the monitor loop."
        ),
    )
    p.add_argument(
        "--scan-min-len", type=int, default=4, metavar="N",
        help="minimum ASCII-run length for --scan-names (default: 4)",
    )
    p.add_argument(
        "--short-names", action="store_true",
        help=(
            "read the abbreviated conglomerate name (Group+0x47, ~12 "
            "chars) instead of the full name (Group+0x08, up to 20 "
            "chars).  Useful for keeping the TUI narrow."
        ),
    )
    p.add_argument(
        "--no-auto-names", action="store_true",
        help=(
            "disable live-memory name discovery.  Labels come from "
            "the JSON mapping only (or fall back to g{recno}).  "
            "Mostly useful for offline testing."
        ),
    )
    # All remaining args are forwarded to live_monitor's own argparser.
    args, rest = p.parse_known_args(argv)
    return args, rest


def main(argv: Optional[Sequence[str]] = None) -> int:
    our_argv = list(sys.argv[1:]) if argv is None else list(argv)
    args, forward = _parse_args(our_argv)

    # Install Windows memory-reader patches BEFORE importing live_monitor
    # triggers LiveGameReader.attach().  The patches mutate
    # caplab_sim.rng_reader in place, so the import order after this
    # point doesn't matter — by the time `attach()` runs the helpers
    # are already the Windows versions on win32.
    _install_windows_patches()

    # Load the JSON name mapping first.  These win over auto-discovered
    # names on a per-recno basis — intentional, so the user can always
    # override an auto-read label (e.g., rename the player corp to
    # "You").
    global NAMES
    json_names = load_names(args.names)

    if args.scan_names:
        # In scan mode we only surface the JSON mapping so the output
        # cross-references user-chosen labels.  Live discovery is
        # unnecessary here because --scan-names prints the raw memory
        # contents anyway.
        NAMES = dict(json_names)
        return _run_scan_names(min_len=args.scan_min_len)

    # Attach to the live game and pull names from memory (unless the
    # user disabled auto-discovery).  Failures here are non-fatal —
    # fall back to JSON + g{recno}.
    auto_names: Dict[int, str] = {}
    if not args.no_auto_names:
        try:
            from caplab_sim.rng_reader import LiveGameReader
            reader = LiveGameReader.attach()
            auto_names = discover_names_from_memory(
                reader, use_short=args.short_names,
            )
        except RuntimeError as exc:
            # Can't attach (game not running, wrong version, etc.) —
            # live_monitor will surface the same error more visibly
            # when it tries to attach for real; here we just warn.
            print(
                f"predictor: live-memory name discovery skipped: {exc}",
                file=sys.stderr,
            )
        except OSError as exc:
            print(
                f"predictor: live-memory name discovery hit OSError: {exc}",
                file=sys.stderr,
            )

    # Merge: auto-discovered first, JSON overrides on top.  This way
    # unspecified recnos pick up their real name, and any override in
    # the JSON file replaces it.
    merged: Dict[int, str] = {}
    merged.update(auto_names)
    merged.update(json_names)
    NAMES = merged

    if auto_names:
        print(
            f"predictor: auto-discovered {len(auto_names)} group name(s) "
            f"from live memory"
            + (f"; {len(json_names)} JSON override(s) applied"
               if json_names else ""),
            file=sys.stderr,
        )

    # Install the label-aware Renderer methods and run() wrapper.  Must
    # happen after caplab_sim.live_monitor is importable; the patches
    # themselves import it lazily.
    _install_label_patches()
    _patch_run()

    from caplab_sim import live_monitor as lm
    return lm.main(forward)


if __name__ == "__main__":
    sys.exit(main())
