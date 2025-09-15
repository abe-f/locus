#!/usr/bin/env python3
import os
import re
import struct
import sys
from collections import defaultdict

RESULTS_BASE = "outputs"

def find_latest_results_root(base=RESULTS_BASE):
    if not os.path.isdir(base):
        raise SystemExit(f"No '{base}' directory found.")
    candidates = []
    for name in os.listdir(base):
        m = re.fullmatch(r"results(\d+)", name)
        if m:
            candidates.append((int(m.group(1)), os.path.join(base, name)))
    if not candidates:
        raise SystemExit("No results<N> directories found under outputs/.")
    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1]

def read_info_command(procdir):
    info_path = os.path.join(procdir, "results.info.txt")
    if not os.path.isfile(info_path):
        return ""
    cmd = ""
    exe = ""
    with open(info_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Cmdline="):
                cmd = line.split("=", 1)[1].strip()
            elif line.startswith("Exe="):
                exe = line.split("=", 1)[1].strip()
    return cmd or exe

def parse_results_out(path):
    with open(path, "rb") as f:
        hdr_size = struct.calcsize("<III I QQ")
        data = f.read(hdr_size)
        if len(data) != hdr_size:
            raise ValueError(f"{path}: header too short")
        magic, version, page_shift, reserved, thread_count, total_entries = struct.unpack("<III I QQ", data)
        if magic != 0x4C4F4353:
            raise ValueError(f"{path}: bad magic (got 0x{magic:08x})")
        if version != 1:
            raise ValueError(f"{path}: unsupported version {version}")

        per_page = defaultdict(lambda: defaultdict(int))
        th_fmt = "<IIQ"; th_size = struct.calcsize(th_fmt)
        kv_fmt = "<QQ";   kv_size = struct.calcsize(kv_fmt)

        for _ in range(thread_count):
            th_data = f.read(th_size)
            if len(th_data) != th_size:
                raise ValueError(f"{path}: thread header truncated")
            tid, _th_reserved, n_entries = struct.unpack(th_fmt, th_data)

            chunk = f.read(n_entries * kv_size)
            if len(chunk) != n_entries * kv_size:
                raise ValueError(f"{path}: kv pairs truncated")

            off = 0
            for _i in range(n_entries):
                vpn, cnt = struct.unpack_from(kv_fmt, chunk, off)
                off += kv_size
                per_page[vpn][tid] += cnt

        return per_page, page_shift

def analyze_pid(per_page):
    local_total = 0
    shared_total = 0
    for _vpn, tmap in per_page.items():
        s = 0
        m = 0
        for c in tmap.values():
            s += c
            if c > m:
                m = c
        local_total += m
        shared_total += (s - m)
    return local_total, shared_total

def main():
    if len(sys.argv) > 1:
        root = sys.argv[1]
        if not os.path.isdir(root):
            raise SystemExit(f"{root} is not a directory")
    else:
        root = find_latest_results_root()

    subdirs = []
    for name in os.listdir(root):
        if re.fullmatch(r"results\d+", name):
            subdirs.append(os.path.join(root, name))
    if not subdirs:
        raise SystemExit(f"No per-PID subdirs found in {root}")

    subdirs.sort(key=lambda p: int(re.search(r"(\d+)$", p).group(1)))

    any_output = False
    for procdir in subdirs:
        m = re.search(r"(\d+)$", procdir)
        if not m:
            continue
        pid = m.group(1)
        results_out = os.path.join(procdir, "results.out")
        if not os.path.isfile(results_out):
            continue
        try:
            per_page, _page_shift = parse_results_out(results_out)
        except Exception as e:
            print(f"[warn] skipping {results_out}: {e}", file=sys.stderr)
            continue

        local_total, shared_total = analyze_pid(per_page)
        total = local_total + shared_total
        local_pct = (100.0 * local_total / total) if total > 0 else 0.0
        command = read_info_command(procdir)

        print(f"pid={pid}, command={command}, local_total={local_total}, shared_total={shared_total}, local (%) = {local_pct:.6f}")
        any_output = True

    if not any_output:
        print("No results.out files parsed.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
