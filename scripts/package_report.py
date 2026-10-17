#!/usr/bin/env python3
"""Validate approved sanitized support evidence and create a verified ZIP.

Reads only the supplied staging tree and optional nonsecret identifier denylist.
Never connects to Timon, reads credentials, or changes the affected installation.
No automatic redaction: a finding blocks delivery and prints no matched value.
"""

import argparse
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tempfile
import zipfile
import zlib


class Rejected(Exception):
    pass


TEXT_EXTENSIONS = {".md", ".json", ".txt", ".csv", ".log", ".yaml", ".yml"}
ROOT_FILES = {"BUG-REPORT.md", "report.json", "README.md", "PRIVACY.md"}
FORBIDDEN_DATA_FILES = {"auth.json", "credentials.json", "cookies.json", "secrets.json", "tokens.json", "config.json", "timon.db"}
REPRO_STATUSES = {
    "observed-existing", "reproduced-fresh", "proposed-only", "not-reproduced"
}
MASKED = re.compile(
    r"^(?:\[REDACTED(?:[:_ -][^\]\r\n]*)?\]|"
    r"<(?:REDACTED|TOKEN|PASSWORD|API_KEY|SECRET)>|"
    r"\$\{?[A-Z_][A-Z0-9_]*\}?|unknown|not.applicable|null|none)$", re.I
)
PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("VENDOR_TOKEN", re.compile(
        r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|"
        r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,}|"
        r"glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
        r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
        r"hf_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{30,})\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("REAL_UUID", re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.I)),
    ("USER_PATH", re.compile(r"/(?:Users|home)/[^/\s<>\"']+|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s<>\"']+")),
    ("URL_CREDENTIALS", re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:<>]+:[^\s/@<>]+@", re.I)),
]
VALUE = r"(\[[^\]\r\n]*\]|<[^>\r\n]*>|[^\s\"'`,;}\]]+)"
ASSIGNMENT = re.compile(
    r"[\"']?\b(?:password(?:[_-]?hash)?|hashed[_-]?password|passwd|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?token|id[_-]?token|"
    r"client[_-]?secret|secret(?:[_-]?key)?|token|bearer)[\"']?\s*[:=]\s*[\"']?" + VALUE, re.I
)
AUTH_HEADER = re.compile(
    r"\b(?:authorization|proxy-authorization)[\"']?\s*[:=]\s*[\"']?"
    r"(?:Bearer|Basic)\s+" + VALUE, re.I
)
BARE_BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9_./+=-]{12,})", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<!\w)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]+(?!\w)", re.I)


def require(condition, message):
    if not condition:
        raise Rejected(message)


def clean_relative(name):
    require(isinstance(name, str) and bool(name), "Evidence path must be a nonempty string")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts, "Unsafe relative path")
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name)), "Invalid evidence filename")
    require(all(not part.startswith(".") for part in path.parts), "Hidden files are not allowed")
    require(path.as_posix() == name, "Evidence path must use canonical forward slashes")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
    require(all(not part.endswith(".") and part.split(".", 1)[0].upper() not in reserved for part in path.parts), "Filename is not portable to Windows")
    return name


def scan_text(name, value, denylist):
    findings = set()
    for line_no, line in enumerate(value.splitlines(), 1):
        for rule, pattern in PATTERNS:
            if pattern.search(line):
                findings.add((line_no, rule))
        for pattern, rule in [(ASSIGNMENT, "SECRET_ASSIGNMENT"), (AUTH_HEADER, "AUTHORIZATION_HEADER"), (BARE_BEARER, "BEARER_TOKEN")]:
            for match in pattern.finditer(line):
                if not MASKED.fullmatch(match.group(1)):
                    findings.add((line_no, rule))
        for pattern in (IPV4, IPV6):
            for match in pattern.finditer(line):
                try:
                    address = ipaddress.ip_address(match.group(0))
                except ValueError:
                    continue
                if not address.is_loopback and not address.is_unspecified:
                    findings.add((line_no, "NETWORK_ADDRESS"))
        for term in denylist:
            start = r"(?<!\w)" if term[0].isalnum() else ""
            end = r"(?!\w)" if term[-1].isalnum() else ""
            if re.search(start + re.escape(term) + end, line, re.I):
                findings.add((line_no, "PRIVATE_IDENTIFIER"))
    if findings:
        locations = "; ".join(f"{name}:{n}:{rule}" for n, rule in sorted(findings))
        raise Rejected("Disclosure gate rejected: " + locations)


def validate_png(name, data):
    require(data.startswith(b"\x89PNG\r\n\x1a\n"), f"{name}: invalid PNG signature")
    safe_chunks = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"pHYs", b"sBIT", b"bKGD"}
    offset, kinds = 8, []
    while offset < len(data):
        require(offset + 12 <= len(data), f"{name}: truncated PNG")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        end = offset + length + 12
        require(end <= len(data), f"{name}: truncated PNG chunk")
        require(kind in safe_chunks, f"{name}: PNG metadata or unsupported chunk; sanitize and review first")
        chunk = data[offset + 8:offset + 8 + length]
        crc = struct.unpack(">I", data[end - 4:end])[0]
        require(zlib.crc32(kind + chunk) & 0xffffffff == crc, f"{name}: PNG CRC failure")
        if kind == b"IHDR":
            require(not kinds and length == 13, f"{name}: invalid PNG header")
            width, height = struct.unpack(">II", chunk[:8])
            require(0 < width * height <= 50_000_000, f"{name}: invalid or excessive image dimensions")
        kinds.append(kind)
        offset = end
        if kind == b"IEND":
            require(length == 0 and offset == len(data), f"{name}: trailing PNG content")
            break
    require(kinds and kinds[0] == b"IHDR" and kinds[-1] == b"IEND" and b"IDAT" in kinds, f"{name}: incomplete PNG")


def walk_error(error):
    raise error


def load_source(source, denylist, reviewed_pngs):
    require(source.is_dir() and not source.is_symlink(), "Source must be an ordinary staging directory")
    result = {}
    names_seen = set()
    total_bytes = 0
    for root, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        for name in dirs:
            path = Path(root) / name
            require(not path.is_symlink(), "Symlink directories are not allowed")
            relative = clean_relative(path.relative_to(source).as_posix())
            scan_text("directory-name", relative, denylist)
            require(relative == "evidence" or relative.startswith("evidence/"), "Only the evidence directory is allowed")
        for name in files:
            path = Path(root) / name
            require(path.is_file() and not path.is_symlink(), "Non-regular files are not allowed")
            relative = clean_relative(path.relative_to(source).as_posix())
            # A private identifier may itself be in a filename. Do not echo it.
            scan_text("file-name", relative, denylist)
            require(path.name.casefold() not in FORBIDDEN_DATA_FILES, "Credential/configuration/database file is not allowed")
            require(relative.casefold() not in names_seen, "Case-insensitive filename collision")
            names_seen.add(relative.casefold())
            require(relative in ROOT_FILES or relative.startswith("evidence/"), f"{relative}: outside file allowlist")
            require(path.stat().st_size < 10_000_000, f"{relative}: individual file too large")
            total_bytes += path.stat().st_size
            require(total_bytes <= 40_000_000, "Evidence tree too large; minimize it")
            require(len(result) < 100, "Too many files; reduce evidence to a focused report")
            data = path.read_bytes()
            if relative in reviewed_pngs:
                require(relative.startswith("evidence/") and path.suffix.lower() == ".png", "Reviewed images must be evidence PNGs")
                validate_png(relative, data)
            else:
                require(path.suffix.lower() in TEXT_EXTENSIONS, f"{relative}: unsupported file or image not explicitly reviewed")
                try:
                    value = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise Rejected(f"{relative}: text is not UTF-8") from None
                require("\x00" not in value, f"{relative}: binary content disguised as text")
                scan_text(relative, value, denylist)
            result[relative] = data
    require(set(reviewed_pngs).issubset(result), "A reviewed PNG was not found in the source")
    require(len(result) <= 100, "Too many files; reduce evidence to a focused report")
    require(sum(map(len, result.values())) <= 40_000_000, "Evidence tree too large; minimize it")
    return result


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "report.json: duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise Rejected("report.json: non-finite number is not valid JSON")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeDecodeError):
        raise Rejected("report.json: invalid JSON") from None


def validate_report(files):
    require(files.get("BUG-REPORT.md", b"").strip(), "BUG-REPORT.md is required and must not be empty")
    require("report.json" in files, "report.json is required")
    report = strict_json(files["report.json"])
    require(isinstance(report, dict) and type(report.get("schema_version")) is int and report["schema_version"] == 1, "report.json: schema_version must be integer 1")
    for key in ["title", "observed_at", "area", "summary", "expected", "actual"]:
        require(isinstance(report.get(key), str) and report[key].strip(), f"report.json: missing nonempty {key}")
    try:
        observed = dt.datetime.fromisoformat(report["observed_at"].replace("Z", "+00:00"))
        require(observed.tzinfo is not None, "report.json: observed_at must include timezone")
    except ValueError:
        raise Rejected("report.json: observed_at must be an ISO timestamp") from None
    environment = report.get("environment")
    require(isinstance(environment, dict), "report.json: environment must be an object")
    for key in ["timon_version", "operating_system", "runtime_mode", "llm_provider", "llm_model"]:
        require(isinstance(environment.get(key), str) and environment[key].strip(), f"report.json: missing environment.{key}; use Unknown if needed")
    reproduction = report.get("reproduction")
    require(isinstance(reproduction, dict), "report.json: reproduction must be an object")
    require(isinstance(reproduction.get("status"), str) and reproduction["status"] in REPRO_STATUSES, "report.json: invalid reproduction.status")
    require(isinstance(reproduction.get("steps"), list) and all(isinstance(s, str) and s.strip() for s in reproduction["steps"]), "report.json: reproduction.steps must be a list of nonempty strings")
    require(isinstance(reproduction.get("limitations"), list) and all(isinstance(s, str) and s.strip() for s in reproduction["limitations"]), "report.json: reproduction.limitations must be a list of nonempty strings")
    for key in ["hypotheses", "unknowns", "evidence"]:
        require(isinstance(report.get(key), list), f"report.json: {key} must be a list")
    require(isinstance(report.get("privacy"), dict) and report["privacy"].get("manually_reviewed") is True, "report.json: explicit manual privacy review is required")
    for item in report["evidence"]:
        require(isinstance(item, dict), "report.json: evidence entries must be objects")
        name = clean_relative(item.get("path", ""))
        require(name.startswith("evidence/") and name in files, "report.json: evidence path not found in evidence directory")
        require(isinstance(item.get("supports"), str) and item["supports"].strip(), "report.json: evidence must state the claim supported")
        require(isinstance(item.get("locator"), str) and item["locator"].strip(), "report.json: evidence must give a locator")
    if reproduction["status"] == "reproduced-fresh":
        require(report["evidence"], "report.json: fresh reproduction needs supporting evidence")
    return report


def main():
    require(sys.version_info >= (3, 10), "Python 3.10 or newer is required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--denylist-file", type=Path, help="Nonsecret private identifiers, one per line, outside source")
    parser.add_argument("--reviewed-png", action="append", default=[], help="Visually reviewed, metadata-free PNG relative path")
    args = parser.parse_args()
    source, output = args.source.absolute(), args.output.absolute()
    require(not source.is_symlink(), "Source symlink is not allowed")
    require(output.suffix.lower() == ".zip", "Output must have a .zip extension")
    require(not output.resolve().is_relative_to(source.resolve()), "Output must be outside the public source tree")
    checksum = output.with_name(output.name + ".sha256")
    checks = output.parent / "package-checks.json"
    for path in [output, checksum, checks]:
        require(not path.exists() and not path.is_symlink(), "Output or sidecar already exists; choose a fresh report directory")
    denylist = []
    if args.denylist_file:
        require(not args.denylist_file.resolve().is_relative_to(source.resolve()), "Private denylist must be outside public staging")
        denylist = [s.strip() for s in args.denylist_file.read_text(encoding="utf-8").splitlines() if s.strip() and not s.lstrip().startswith("#")]
    reviewed = {clean_relative(name) for name in args.reviewed_png}
    files = load_source(source, denylist, reviewed)
    validate_report(files)
    manifest = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n" for name, data in sorted(files.items()))
    files["SHA256SUMS"] = manifest.encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo("timon-bug-report/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    payload = buffer.getvalue()
    require(len(payload) < 10_000_000, "ZIP exceeds conservative 10 MB upload limit; minimize evidence")
    with tempfile.TemporaryDirectory(prefix="timon-report-verify-") as temp:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            require(archive.testzip() is None, "ZIP CRC verification failed")
            require(set(archive.namelist()) == {"timon-bug-report/" + name for name in files}, "Unexpected ZIP entries")
            archive.extractall(temp)
        extracted = Path(temp) / "timon-bug-report"
        for name, data in files.items():
            received = (extracted / name).read_bytes()
            require(hashlib.sha256(received).digest() == hashlib.sha256(data).digest(), "Extracted SHA-256 mismatch")
            if name in reviewed:
                validate_png(name, received)
            else:
                scan_text(name, received.decode("utf-8"), denylist)
        validate_report({name: (extracted / name).read_bytes() for name in files if name != "SHA256SUMS"})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(payload)
    digest = hashlib.sha256(payload).hexdigest()
    with checksum.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(digest + "  " + output.name + "\n")
    with checks.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump({
            "schema_version": 1,
            "archive_bytes": len(payload),
            "archive_sha256": digest,
            "files": sorted(files),
            "checks": {"report_schema": "passed", "builtin_disclosure_scan": "passed", "known_identifier_scan": "passed" if denylist else "not-configured", "extracted_tree_rescan": "passed", "zip_crc": "passed", "sha256_manifest": "passed"},
            "reviewed_pngs": sorted(reviewed),
            "limits": ["Pattern scan is not complete anonymization", "Screenshot pixels require prior visual review", "No production behavior or causal claim was tested", "Workspace-mandated external scanners must be run separately when applicable"]
        }, handle, indent=2)
        handle.write("\n")
    print(f"Created {output.name}: {len(payload)} bytes; {len(files)} files")
    print("Schema, disclosure scan, extracted rescan, CRC and SHA-256 checks passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Rejected, OSError, UnicodeError) as error:
        # OSError details may contain private paths: print only the error class.
        message = str(error) if isinstance(error, Rejected) else type(error).__name__
        print("Rejected: " + message, file=sys.stderr)
        raise SystemExit(2)
