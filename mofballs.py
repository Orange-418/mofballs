#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass
from typing import Literal

FilterKind = Literal["process_name", "process_name_contains", "process_commandline_contains"]


def _mof_escape_string(s: str) -> str:
    """Escape for double-quoted MOF string literals."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _wql_string_literal(s: str) -> str:
    """Single-quoted WQL literal; double embedded quotes per WQL rules."""
    return s.replace("'", "''")


@dataclass(frozen=True)
class BuiltFilter:
    name: str
    query: str


def build_event_filter(
    kind: FilterKind,
    match: str,
    event_namespace: str = "root\\\\cimv2",
    poll_interval_sec: int = 1,
) -> BuiltFilter:
    """
    Build __EventFilter query for __InstanceCreationEvent on Win32_Process.
    """
    m = _wql_string_literal(match)
    base = (
        f"SELECT * FROM __InstanceCreationEvent WITHIN {poll_interval_sec} "
        "WHERE TargetInstance ISA 'Win32_Process'"
    )
    if kind == "process_name":
        suffix = f" AND TargetInstance.Name = '{m}'"
    elif kind == "process_name_contains":
        suffix = f" AND TargetInstance.Name LIKE '%{m}%'"
    elif kind == "process_commandline_contains":
        suffix = f" AND TargetInstance.CommandLine LIKE '%{m}%'"
    else:
        raise ValueError(f"unknown filter kind: {kind}")

    name = f"EvtF_{uuid.uuid4().hex[:12]}"
    q = base + suffix
    return BuiltFilter(name=name, query=q)


def build_mof(
    *,
    filter_kind: FilterKind,
    match: str,
    command_line_template: str,
    poll_interval: int,
    event_namespace: str,
) -> str:
    bf = build_event_filter(
        filter_kind, match, event_namespace=event_namespace, poll_interval_sec=poll_interval
    )
    cons_name = f"Cons_{uuid.uuid4().hex[:12]}"
    bind_name = f"Bind_{uuid.uuid4().hex[:12]}"

    filter_block = f"""instance of __EventFilter as $F
{{
    Name = "{bf.name}";
    EventNamespace = "{event_namespace}";
    QueryLanguage = "WQL";
    Query = "{_mof_escape_string(bf.query)}";
}};
"""

    cmd = _mof_escape_string(command_line_template)
    consumer_block = f"""instance of CommandLineEventConsumer as $C
{{
    Name = "{cons_name}";
    CommandLineTemplate = "{cmd}";
}};
"""

    binding_block = f"""instance of __FilterToConsumerBinding
{{
    Filter = $F;
    Consumer = $C;
}};
"""

    # Line 1 must be #pragma autorecover so mofcomp registers this path for repository rebuild.
    # mofcomp does not accept # comments; use // only. Keep header ASCII-only.
    header = f"""#pragma autorecover
#pragma namespace("\\\\\\\\.\\\\root\\\\subscription")
"""
    return header + filter_block + "\n" + consumer_block + "\n" + binding_block


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate WMI permanent subscription MOF (event filter + CommandLineEventConsumer + binding).",
        epilog=(
            "Examples:\n"
            "  %(prog)s --filter process_name --match notepad.exe "
            '--command-line-template "cmd.exe /c echo triggered"\n'
            "  %(prog)s --filter process_commandline_contains --match -enc "
            '--command-line-template "cmd.exe /c echo lab-only"\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--filter",
        dest="filter_kind",
        choices=("process_name", "process_name_contains", "process_commandline_contains"),
        default="process_name",
        help="Event filter: Win32_Process creation match type (default: process_name).",
    )
    p.add_argument(
        "--match",
        required=True,
        help="String to match (exe name, substring in name, or substring in command line).",
    )
    p.add_argument(
        "--poll-within",
        type=int,
        default=1,
        metavar="SEC",
        help="WITHIN interval for __InstanceCreationEvent polling (default: 1).",
    )
    p.add_argument(
        "--event-namespace",
        default="root\\\\cimv2",
        help='WQL event source namespace (default: root\\\\cimv2).',
    )
    p.add_argument(
        "--command-line-template",
        required=True,
        help='CommandLineEventConsumer CommandLineTemplate (e.g. cmd.exe /c ...). WMI %% substitution is supported.',
    )
    p.add_argument("-o", "--output", help="Write MOF to file; default: stdout.")
    p.add_argument(
        "--json-meta",
        action="store_true",
        help="Print one JSON line to stderr with filter name and warnings.",
    )

    args = p.parse_args(argv)

    try:
        mof = build_mof(
            filter_kind=args.filter_kind,
            match=args.match,
            command_line_template=args.command_line_template,
            poll_interval=args.poll_within,
            event_namespace=args.event_namespace,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(mof)
    else:
        sys.stdout.write(mof)

    if args.json_meta:
        bf = build_event_filter(
            args.filter_kind,
            args.match,
            event_namespace=args.event_namespace,
            poll_interval_sec=args.poll_within,
        )
        meta = {
            "filter_name": bf.name,
            "consumer": "CommandLineEventConsumer",
            "warning": "Install with mofcomp or WMI APIs only on authorized systems.",
        }
        print(json.dumps(meta), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

