"""Offline ArcSight SmartConnector parse-compat simulator for CyberRange catalogs.

Emulates the parser families found in the (proprietary, NOT in this repo)
ArcSight SmartConnector unobfuscated parser bundle:
  * sdkrfilereader        top regex + submessage/pattern regex tables, fullmatch semantics
  * sdkkeyvaluefilereader typed key=value tokenizer; unknown keys -> additionaldata
  * cef_syslog            CEF header + typed extension tokens
  * jsonparser            token[i].location presence
and reports, per catalog, whether generated samples land on a *specific* pattern
or fall through to a catch-all / unparsed state.

The parser bundle is OpenText-proprietary and is never committed. Point the
`ARCSIGHT_PARSERS` env var at a local extraction (directory tree with the
bundle's backslash paths normalised to `/`, e.g. `cef_syslog/cef_syslog.
sdkkeyvaluefilereader.properties`). When unset, `test_arcsight_compat.py`
skips and `python tests/arcsight/arcsight_sim.py` refuses to run.

Verdict vocabulary (best → worst): OK > WARN > PARTIAL > CATCH-ALL > FAIL;
N/A = the bundle has no parser for that wire format (documented, not a bug).
"""
from __future__ import annotations

import json
import os
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(os.environ["ARCSIGHT_PARSERS"]) if os.environ.get("ARCSIGHT_PARSERS") else None
SAMPLES_PER_CATALOG = 5
VERDICT_RANK = {"OK": 0, "WARN": 1, "PARTIAL": 2, "CATCH-ALL": 3, "FAIL": 4, "N/A": 5}

IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SYSLOG_3164 = re.compile(r"^<\d+>(?:\w{3} +\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}) (\S+) (.*)$", re.S)
PROC = re.compile(r"^([A-Za-z0-9_./ -]+?)(?:\[(\d+)\])?:\s*(.*)$", re.S)


# ----------------------------------------------------------------------------- props
def load_props(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines: list[str] = []
    buf = ""
    for ln in raw.splitlines():
        if buf:
            ln = ln.lstrip()
        if ln.endswith("\\") and not ln.endswith("\\\\"):
            buf += ln[:-1]
            continue
        lines.append(buf + ln)
        buf = ""
    props: dict[str, str] = {}
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([^=:\s]+(?:\\[=:][^=:\s]*)*)\s*[=:]\s*(.*)$", ln)
        if not m:
            continue
        props[m.group(1).replace("\\=", "=").replace("\\:", ":")] = m.group(2)
    return props


def java_rx(s: str) -> str:
    # properties-level unescape: `\\` -> `\`, `\=`/`\:` -> literal
    return s.replace("\\\\", "\\").replace("\\=", "=").replace("\\:", ":")


def compile_rx(s: str) -> re.Pattern | None:
    try:
        return re.compile(java_rx(s), re.S)
    except re.error:
        try:  # java-only constructs: possessive quantifiers / atomic groups
            return re.compile(re.sub(r"(?<=[+*?}])\+", "", java_rx(s)).replace("(?>", "(?:"), re.S)
        except re.error:
            return None


# ----------------------------------------------------------------------------- regex parser
@dataclass
class Pattern:
    idx: int
    rx: str
    fields: list[str]
    compiled: re.Pattern | None

    @property
    def is_catch_all(self) -> bool:
        core = re.sub(r"\(\?[a-z]+\)", "", java_rx(self.rx))
        return core in {"(.*)", "(.*?)", ".*", "(.+)"} or bool(re.fullmatch(r"\(\.\*\??\)(?:\(\?:[^)]*\)\??)*", core))


@dataclass
class SubMessage:
    idx: int
    ids: list[str]
    patterns: list[Pattern]


@dataclass
class RegexParser:
    name: str
    top: re.Pattern | None
    tokens: list[str]
    mid_token: str | None
    body_token: str | None
    subs: list[SubMessage]

    @classmethod
    def load(cls, path: Path) -> "RegexParser":
        p = load_props(path)
        top = compile_rx(p["regex"]) if "regex" in p else None
        n = int(p.get("token.count", "0") or 0)
        tokens = [p.get(f"token[{i}].name", f"t{i}") for i in range(n)]
        subs = []
        for k, v in p.items():
            m = re.fullmatch(r"submessage\[(\d+)\]\.messageid", k)
            if m:
                subs.append(SubMessage(int(m.group(1)), [s.strip() for s in v.split(",")], []))
        if not subs and any(k.startswith("submessage[0].pattern") for k in p):
            subs.append(SubMessage(0, [""], []))
        for sm in subs:
            for k, v in p.items():
                m = re.fullmatch(rf"submessage\[{sm.idx}\]\.pattern\[(\d+)\]\.regex", k)
                if m:
                    i = int(m.group(1))
                    flds = p.get(f"submessage[{sm.idx}].pattern[{i}].fields", "")
                    sm.patterns.append(Pattern(i, v, [f.strip() for f in flds.split(",") if f.strip()], compile_rx(v)))
            sm.patterns.sort(key=lambda x: x.idx)
        subs.sort(key=lambda s: s.idx)
        return cls(path.stem, top, tokens, p.get("submessage.messageid.token"), p.get("submessage.token"), subs)

    def run(self, body: str, module: str | None = None) -> dict:
        res: dict = {"parser": self.name, "top": None, "mid": None, "sub": None, "pattern": None, "catch_all": False, "fields": []}
        toks: dict[str, str] = {}
        if self.top is not None:
            m = self.top.fullmatch(body) or self.top.match(body)
            if not m:
                res["top"] = "NO-MATCH"
                return res
            res["top"] = "full" if m.end() == len(body) else "prefix"
            toks = {self.tokens[i]: (m.group(i + 1) or "") for i in range(min(len(self.tokens), m.lastindex or 0))}
        else:
            res["top"] = "none"
        mid = None
        if self.mid_token:
            mid = module if self.mid_token == "Module" and module is not None else toks.get(self.mid_token)
        res["mid"] = mid
        sub_body = toks.get(self.body_token, body) if self.body_token else body
        if not self.subs:
            res.update(sub="top", pattern="top", catch_all=False, fields=[t for t in self.tokens if toks.get(t)])
            return res
        cands = [s for s in self.subs if mid is not None and mid in s.ids] or ([s for s in self.subs if s.ids == [""]] if mid is None else [])
        if not cands:
            res["sub"] = f"no submessage for messageid={mid!r}"
            return res
        for sm in cands:
            for pt in sm.patterns:
                if pt.compiled is None:
                    continue
                if pt.compiled.fullmatch(sub_body):
                    res.update(sub=sm.idx, pattern=pt.idx, catch_all=pt.is_catch_all, fields=pt.fields)
                    return res
        res["sub"] = f"submessage {[s.idx for s in cands]} – none of {sum(len(s.patterns) for s in cands)} patterns fullmatch"
        return res


# ----------------------------------------------------------------------------- kv parser
@dataclass
class KVParser:
    name: str
    types: dict[str, str]
    mapped: set[str]
    key_rx: re.Pattern
    kv_delim: str
    delim_rx: re.Pattern
    qualifier: str

    @classmethod
    def load(cls, path: Path) -> "KVParser":
        p = load_props(path)
        n = int(p.get("token.count", "0") or 0)
        types = {p[f"token[{i}].name"]: p.get(f"token[{i}].type", "String") for i in range(n) if f"token[{i}].name" in p}
        mapped = set()
        for k, v in p.items():
            if k.startswith("event.") or k.startswith("additionaldata."):
                mapped.update(re.findall(r"(?<![\w\"'])([A-Za-z_][\w.-]*)(?![\w(\"'])", v))
        return cls(
            path.stem, types, mapped,
            re.compile(java_rx(p.get("key.regexp", r"([^=\s]+)"))),
            java_rx(p.get("key.value.delimiter", "=")),
            re.compile(java_rx(p.get("key.delimiter", r"\s+"))),
            java_rx(p.get("text.qualifier", '"')),
        )

    def tokenize_cef(self, ext: str) -> dict[str, str]:
        rx = re.compile(r"(?:^|\s)([A-Za-z_][\w.]*)=((?:(?!\s[A-Za-z_][\w.]*=).)*)")
        return {m.group(1): m.group(2).strip() for m in rx.finditer(ext)}

    def tokenize(self, body: str) -> dict[str, str]:
        q = re.escape(self.qualifier)
        kvd = re.escape(self.kv_delim)
        rx = re.compile(rf"{self.key_rx.pattern}{kvd}(?:{q}((?:[^{q}\\]|\\.)*){q}|(\S*))")
        out: dict[str, str] = {}
        for m in rx.finditer(body):
            out[m.group(1)] = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        return out

    def run(self, body: str, cef: bool = False) -> dict:
        kv = self.tokenize_cef(body) if cef else self.tokenize(body)
        known = {k for k in kv if k in self.types or k in self.mapped}
        typed_bad = []
        for k, v in kv.items():
            t = self.types.get(k)
            if not v or not t:
                continue
            if t in ("Integer", "Long") and not re.fullmatch(r"-?\d+", v):
                typed_bad.append(f"{k}={v!r} not {t}")
            elif t == "IPAddress" and not IPV4.match(v):
                typed_bad.append(f"{k}={v!r} not IPv4")
        return {"parser": self.name, "keys": len(kv), "known": len(known), "unknown": sorted(set(kv) - known), "typed_bad": typed_bad}


# ----------------------------------------------------------------------------- cef
CEF_KV = None


def split_cef(body: str) -> tuple[list[str], str] | None:
    m = re.search(r"CEF:(\d+)\|", body)
    if not m:
        return None
    rest = body[m.end():]
    parts, cur, i = [], "", 0
    while i < len(rest) and len(parts) < 6:
        c = rest[i]
        if c == "\\" and i + 1 < len(rest):
            cur += rest[i:i + 2]
            i += 2
            continue
        if c == "|":
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    return [m.group(1)] + parts, rest[i:]


def run_cef(body: str) -> dict:
    sp = split_cef(body)
    if not sp:
        return {"parser": "cef_syslog", "error": "no CEF: header"}
    hdr, ext = sp
    issues = []
    if len(hdr) != 7:
        issues.append(f"header has {len(hdr)} fields (need 7)")
    elif hdr[6].strip() not in {"Low", "Medium", "High", "Very-High"} and not (re.fullmatch(r"\d{1,2}", hdr[6].strip()) and 0 <= int(hdr[6]) <= 10):
        issues.append(f"severity {hdr[6]!r} not 0-10/Low/Medium/High/Very-High")
    # unescaped '=' inside values breaks the tokenizer
    for m in re.finditer(r"(?<!\\)=", ext):
        pass
    kv = CEF_KV.run(ext, cef=True)
    tokens = CEF_KV.tokenize_cef(ext)
    rt = tokens.get("rt")
    if rt and not (re.fullmatch(r"\d{10,13}", rt) or re.fullmatch(r"\w{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \S+)?", rt) or re.fullmatch(r"\d{4}-\d{2}-\d{2}[T ].*", rt)):
        issues.append(f"rt={rt!r} not a standard CEF timestamp")
    bad_eq = [k for k, v in tokens.items() if re.search(r"(?<!\\)=", v)]
    if bad_eq:
        issues.append(f"unescaped '=' inside value of {bad_eq[:3]} (ArcSight would split it into a bogus key)")
    odd = [k for k in tokens if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", k)]
    if odd:
        kv.setdefault("notes", []).append("non-standard key names → additionaldata: " + ",".join(odd[:6]))
    kv.update(parser="cef_syslog", header=hdr, issues=issues + kv["typed_bad"])
    return kv


# ----------------------------------------------------------------------------- json
def run_json(body: str, parser_files: list[Path]) -> dict:
    try:
        doc = json.loads(body)
    except json.JSONDecodeError as e:
        return {"parser": "jsonparser", "error": f"invalid JSON: {e}"}
    want: dict[str, str] = {}
    for f in parser_files:
        p = load_props(f)
        for k, v in p.items():
            m = re.fullmatch(r"token\[(\d+)\]\.location", k)
            if m:
                want[p.get(f"token[{m.group(1)}].name", v)] = v
    missing, present = [], []
    for name, loc in want.items():
        cur = doc
        ok = True
        for seg in loc.strip("/").replace("$.", "").split("/" if "/" in loc else "."):
            hit = next((k for k in cur if k.lower() == seg.lower()), None) if isinstance(cur, dict) else None
            if hit is not None:
                cur = cur[hit]
            else:
                ok = False
                break
        (present if ok else missing).append(name)
    return {"parser": ",".join(f.stem for f in parser_files), "present": len(present), "missing": missing, "total": len(want)}


# ----------------------------------------------------------------------------- pre-processors
def after_host(line: str) -> tuple[str, str | None]:
    m = SYSLOG_3164.match(line)
    return (m.group(2), None) if m else (re.sub(r"^<\d+>", "", line), None)


def syslog_split(line: str) -> tuple[str, str | None]:
    body, _ = after_host(line)
    m = PROC.match(body)
    return (m.group(3), m.group(1).strip()) if m else (body, None)


def raw(line: str) -> tuple[str, str | None]:
    return line, None


def netscaler(line: str) -> tuple[str, str | None]:
    return re.sub(r"^.*?<\w+\.\w+>\s*", "", line), None


def after_proc_kv(line: str) -> tuple[str, str | None]:
    body, _ = after_host(line)
    m = PROC.match(body)
    return (m.group(3) if m else body), None


# ----------------------------------------------------------------------------- catalog map
# kind: regex | kv | cef | json | na
SPEC: dict[str, dict] = {
    "apache/httpd/2.4/access-combined": dict(kind="regex", file="apache/apache_access_file.sdkrfilereader.properties", pre=raw),
    "aws/cloudtrail/2.0/credential-abuse-teampcp": dict(kind="json", files=["amazon_cloudtrail/common.jsonparser.properties", "amazon_cloudtrail/default_service.jsonparser.properties"]),
    "cisco/asa/9.18/connection": dict(kind="regex", file="ciscopix/ciscopix.subagent.sdkrfilereader.properties", pre=after_host),
    "cisco/firepower/7.x/intrusion-event": dict(kind="regex", file="ciscopix/ciscopix.subagent.sdkrfilereader.properties", pre=after_host, alt="sourcefire/sourcefire.subagent.sdkrfilereader.properties"),
    "citrix/netscaler/13.x/waf-violation-native": dict(kind="regex", file="citrixnetscaler_syslog/citrixnetscaler_syslog.subagent.sdkrfilereader.properties", pre=netscaler),
    "f-secure/policy-manager/15.x/av-detect-native": dict(kind="regex", file="fsecure_file/fsecure_file.sdkrfilereader.properties", pre=after_proc_kv, note="ArcSight only ships the PM *file* format (TrapNumber=…); syslog 'F-Secure: Virus Alert!' has no parser"),
    "f5/asm/16.x/violation": dict(kind="na", note="f5bigip_syslog covers TMOS system logs only; ASM key=value request log has no parser (ArcSight path = ASM CEF logging profile)"),
    "fortinet/fortios/7.4/traffic": dict(kind="kv", file="fortigate/fortigate.sdkkeyvaluefilereader.properties", pre=after_host),
    "fortinet/fortios/7.4/fortios.event.vpn.sslvpn_auth.fortibleed": dict(kind="kv", file="fortigate/fortigate.sdkkeyvaluefilereader.properties", pre=after_host),
    "fortinet/fortios/7.4/utm-webfilter-litellm-c2-teampcp": dict(kind="kv", file="fortigate/fortigate.sdkkeyvaluefilereader.properties", pre=after_host),
    "fortinet/fortiweb/7.x/attack-log": dict(kind="na", note="no FortiWeb parser in 8.5.2 bundle (FortiWeb → CEF recommended)"),
    "imperva/securesphere/14.x/waf-alert-native": dict(kind="na", note="no SecureSphere parser (Imperva ships CEF natively)"),
    "kaspersky/ksc/13.x/av-detect-native": dict(kind="na", note="only kaspersky_db (KSC SQL pull); RFC5424 SD syslog unsupported"),
    "kubernetes/k8s-audit/1.x/daemonset-create-teampcp": dict(kind="na", note="no k8s audit parser"),
    "linux/auditd/3.x/execve-pip-install-teampcp": dict(kind="regex", file="syslog/merge/linux_auditd/linux_auditd.subagent.sdkrfilereader.properties", pre=after_host, kv="linux_auditd/linux_auditd.sdkkeyvaluefilereader.properties"),
    "linux/auditd/3.x/file-create-teampcp": dict(kind="regex", file="syslog/merge/linux_auditd/linux_auditd.subagent.sdkrfilereader.properties", pre=after_host, kv="linux_auditd/linux_auditd.sdkkeyvaluefilereader.properties"),
    "linux/openssh/9.x/auth-failure": dict(kind="regex", file="syslog/syslog.subagent.sdkrfilereader.properties", pre=syslog_split),
    "mcafee/epo/5.10/av-detect": dict(kind="na", note="ePO XML-over-syslog: bundle only has epo_db/trellix_epo_db (SQL pull)"),
    "mcafee/epo/5.10/exploit-prevent": dict(kind="na", note="ePO XML-over-syslog: bundle only has epo_db/trellix_epo_db (SQL pull)"),
    "microsoft/windows/2022/security-4624-logon": dict(kind="na", note="winc parsers consume WinC agent events, not winlogbeat JSON"),
    "microsoft/windows/2022/security-4672-privileged": dict(kind="na", note="winc/WinC agent only"),
    "microsoft/windows/2022/security-4720-account-create": dict(kind="na", note="winc/WinC agent only"),
    "microsoft/windows/2022/sysmon-network-connect-teampcp": dict(kind="na", note="winc/microsoft_windows_sysmon_operational via WinC agent only"),
    "microsoft/windows/2022/sysmon-v15": dict(kind="na", note="winc/microsoft_windows_sysmon_operational via WinC agent only"),
    "nginx/access/1.x/access-native": dict(kind="regex", file="apache/apache_access_file.sdkrfilereader.properties", pre=raw, note="no nginx parser; nearest is apache combined-log"),
    "owasp/modsecurity-crs/4.x/audit-json": dict(kind="na", note="no ModSecurity parser"),
    "paloalto/panos/11.x/threat": dict(kind="na", note="PAN-OS CSV syslog has no parser in bundle; ArcSight expects PAN CEF"),
    "paloalto/panos/11.x/traffic": dict(kind="na", note="PAN-OS CSV syslog has no parser in bundle; ArcSight expects PAN CEF"),
    "paloalto/panos/11.x/threat-leef": dict(kind="na", note="LEEF is IBM QRadar-native; no ArcSight parser"),
    "symantec/endpoint-protection/14.x/av-detect": dict(kind="regex", file="symantecendpointprotection_syslog/symantecendpointprotection_regex.sdkrfilereader.properties", pre=lambda l: (re.sub(r"^.*?SymantecServer:\s+", "", after_host(l)[0]), None)),
    "symantec/endpoint-protection/14.x/sonar-detect": dict(kind="regex", file="symantecendpointprotection_syslog/symantecendpointprotection_regex.sdkrfilereader.properties", pre=lambda l: (re.sub(r"^.*?SymantecServer:\s+", "", after_host(l)[0]), None)),
    "trendmicro/apex-one/14.x/av-detect-native": dict(kind="na", note="only trendmicro*_db (SQL pull); Apex Central syslog key=value unsupported → CEF sibling is the ArcSight path"),
    "trendmicro/apex-one/14.x/web-reputation-native": dict(kind="na", note="only trendmicro*_db (SQL pull)"),
}


# ----------------------------------------------------------------------------- driver
@dataclass(frozen=True)
class AuditResult:
    catalog: str
    kind: str
    verdict: str
    summary: str
    trace: tuple[str, ...] = ()


def parsers_available(root: Path | None = ROOT) -> bool:
    return bool(root) and (root / "cef_syslog/cef_syslog.sdkkeyvaluefilereader.properties").is_file()


def catalog_key(path: Path, catalog_root: Path) -> str:
    """`<catalog>/f5/asm/16.x/violation-cef.yaml` -> `f5/asm/16.x/violation-cef`."""
    return path.relative_to(catalog_root).with_suffix("").as_posix()


def _audit_cef(lines: list[str]) -> tuple[str, str]:
    rs = [run_cef(l) for l in lines]
    issues = sorted({i for r in rs for i in r.get("issues", [])} | {r["error"] for r in rs if "error" in r})
    unknown = sorted({u for r in rs for u in r.get("unknown", [])})
    hdr = rs[0].get("header", [])
    verdict = "FAIL" if any("error" in r for r in rs) or any("header" in i or "severity" in i for i in issues) else ("WARN" if issues else "OK")
    summary = f"hdr={'|'.join(hdr[1:4])}; known {rs[0].get('known')}/{rs[0].get('keys')} ext keys"
    if unknown:
        summary += f"; → additionaldata: {','.join(unknown[:6])}{'…' if len(unknown) > 6 else ''}"
    if issues:
        summary += "; ISSUES: " + " / ".join(issues)
    return verdict, summary


def _audit_kv(spec: dict, lines: list[str], root: Path) -> tuple[str, str]:
    kvp = KVParser.load(root / spec["file"])
    rs = [kvp.run(spec["pre"](l)[0]) for l in lines]
    unknown = sorted({u for r in rs for u in r["unknown"]})
    bad = sorted({b for r in rs for b in r["typed_bad"]})
    summary = f"{kvp.name}: known {rs[0]['known']}/{rs[0]['keys']} keys; → additionaldata: {','.join(unknown[:10])}{'…' if len(unknown) > 10 else ''}"
    if bad:
        summary += "; TYPE: " + " / ".join(bad[:4])
    return ("WARN" if bad else "OK"), summary


def _audit_regex(spec: dict, lines: list[str], root: Path) -> tuple[str, str, list[str]]:
    rp = RegexParser.load(root / spec["file"])
    alt = RegexParser.load(root / spec["alt"]) if spec.get("alt") else None
    outs, trace = [], []
    for l in lines:
        body, module = spec["pre"](l)
        r = rp.run(body, module)
        if r["pattern"] is None and alt:
            r2 = alt.run(body, module)
            if r2["pattern"] is not None:
                r = r2
        outs.append(r)
        trace.append(f"{json.dumps({k: v for k, v in r.items() if k != 'fields'}, ensure_ascii=False)} :: {body[:90]}")
    specific = [r for r in outs if r["pattern"] is not None and not r["catch_all"]]
    catch = [r for r in outs if r["catch_all"]]
    if len(specific) == len(outs):
        verdict = "OK"
        pats = sorted({f"{r['parser']}#{r['sub']}.{r['pattern']}" if r['sub'] != 'top' else f"{r['parser']} top-regex ({len(r['fields'])} tokens)" for r in outs})
        summary = f"specific pattern(s) {', '.join(pats[:4])}; fields={outs[0]['fields'][:6]}"
    elif catch and not specific:
        verdict = "CATCH-ALL"
        summary = f"{outs[0]['parser']}: only catch-all pattern #{outs[0]['pattern']} ({','.join(outs[0]['fields'])}) — vendor fields lost"
    elif specific:
        verdict = "PARTIAL"
        rest = next(r for r in outs if r not in specific)
        summary = f"{len(specific)}/{len(outs)} samples on specific patterns; rest: {rest['sub']}"
    else:
        verdict = "FAIL"
        summary = f"{outs[0]['parser']}: top={outs[0]['top']} mid={outs[0]['mid']!r} → {outs[0]['sub']}"
    if spec.get("kv") and outs[0]["top"] != "NO-MATCH":
        kvp = KVParser.load(root / spec["kv"])
        kr = kvp.run(re.sub(r"^.*?audit\([^)]*\):\s*", "", spec["pre"](lines[0])[0]))
        summary += f"; kv known {kr['known']}/{kr['keys']}" + (f", unknown {kr['unknown'][:8]}" if kr["unknown"] else "")
    if spec.get("note"):
        summary += f" [{spec['note']}]"
    return verdict, summary, trace


def audit_catalog(key: str, lines: list[str], root: Path | None = ROOT) -> AuditResult:
    """Run the emulated ArcSight parse over rendered sample lines of one catalog."""
    global CEF_KV
    if not parsers_available(root):
        raise RuntimeError("ARCSIGHT_PARSERS is unset or does not point at an extracted parser bundle")
    if CEF_KV is None:
        CEF_KV = KVParser.load(root / "cef_syslog/cef_syslog.sdkkeyvaluefilereader.properties")
    is_cef = any("CEF:" in l for l in lines[:2])
    spec = SPEC.get(key) or (dict(kind="cef") if is_cef else dict(kind="na", note="unmapped: no ArcSight parser assigned in SPEC"))
    if spec["kind"] == "na" and is_cef:
        spec = dict(kind="cef")
    kind = spec["kind"]
    trace: list[str] = []
    if kind == "na":
        verdict, summary = "N/A", spec["note"]
    elif kind == "cef":
        verdict, summary = _audit_cef(lines)
    elif kind == "json":
        r = run_json(lines[0], [root / f for f in spec["files"]])
        verdict = "FAIL" if "error" in r else ("WARN" if r["missing"] else "OK")
        summary = r.get("error") or f"{r['present']}/{r['total']} token locations present" + (f"; missing {r['missing']}" if r["missing"] else "")
    elif kind == "kv":
        verdict, summary = _audit_kv(spec, lines, root)
    else:
        verdict, summary, trace = _audit_regex(spec, lines, root)
    return AuditResult(key, kind, verdict, summary, tuple(trace))


def render_samples(spec, n: int = SAMPLES_PER_CATALOG, seed: int | None = None) -> list[str]:
    import random
    from cyberrange import render_one
    if seed is not None:
        random.seed(seed)
    return [render_one(spec, {}) for _ in range(n)]


def audit_all(root: Path | None = ROOT, n: int = SAMPLES_PER_CATALOG) -> list[AuditResult]:
    from cyberrange.loader import CATALOG_ROOT, list_specs
    out = []
    for path, spec in list_specs(CATALOG_ROOT):
        key = catalog_key(path, CATALOG_ROOT)
        out.append(audit_catalog(key, render_samples(spec, n, seed=zlib.crc32(key.encode())), root))
    return sorted(out, key=lambda r: (VERDICT_RANK[r.verdict], r.catalog))


def main() -> None:
    if not parsers_available(ROOT):
        sys.exit("ARCSIGHT_PARSERS is unset or invalid — point it at an extracted SmartConnector parser bundle")
    results = audit_all()
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print(f"Totals: {counts}")
    for r in results:
        print(f"{r.verdict:9} {r.kind:5} {r.catalog}\n          {r.summary[:230]}")
    if "--trace" in sys.argv:
        for r in results:
            if r.trace:
                print(f"\n### {r.catalog}\n" + "\n".join("    " + t for t in r.trace))


if __name__ == "__main__":
    main()
