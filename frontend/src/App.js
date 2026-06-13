/* eslint-disable */
import React, { useState, useEffect, useRef, useCallback } from "react";
import { scanFiles, getHistory, quarantineFile, getEngineStatus, deleteScan } from "./api";
import "./App.css";

const fmt = (n) => {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
};
const getNow = () => new Date().toTimeString().slice(0, 8);
const SEV_ORDER = ["critical", "high", "medium", "low", "info", "clean"];

export default function App() {
  const [files, setFiles]         = useState([]);
  const [dragOver, setDragOver]   = useState(false);
  const [phase, setPhase]         = useState("idle");
  const [uploadPct, setUploadPct] = useState(0);
  const [results, setResults]     = useState([]);
  const [activeResult, setActive] = useState(null);
  const [history, setHistory]     = useState([]);
  const [engineStatus, setStatus] = useState(null);
  const [logs, setLogs]           = useState([]);
  const [tab, setTab]             = useState("scan");
  const fileRef                   = useRef();
  const termRef                   = useRef();

  const log = useCallback((msg, type) => {
    setLogs((l) => [...l.slice(-80), { ts: getNow(), msg, type: type || "info" }]);
  }, []);

  useEffect(() => {
    getEngineStatus().then((r) => setStatus(r.data)).catch(() => setStatus({ error: "Backend offline" }));
    getHistory().then((r) => setHistory(r.data.scans || [])).catch(() => {});
    log("NeuroVirus UI connected to backend", "ok");
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logs]);

  const handleFiles = (fl) => {
    const arr = Array.from(fl);
    setFiles(arr);
    setPhase("idle");
    setResults([]);
    setActive(null);
    log(arr.length + " file(s) queued", "info");
  };

  const startScan = async () => {
    if (!files.length) return;
    setPhase("uploading");
    setResults([]);
    setActive(null);
    log("Uploading to NeuroVirus backend...", "info");
    try {
      const resp = await scanFiles(files, (e) => {
        const pct = Math.round((e.loaded / e.total) * 100);
        setUploadPct(pct);
        if (pct === 100) { setPhase("scanning"); log("Upload complete. Running analysis...", "ok"); }
      });
      const data = resp.data;
      setResults(data.results || []);
      if (data.results && data.results.length) setActive(data.results[0]);
      setPhase("done");
      log("Scan complete: " + data.scanned + " file(s)", "ok");
      (data.results || []).forEach((r) => {
        const t = (r.threat_level === "CRITICAL" || r.threat_level === "HIGH") ? "err" : r.threat_level === "MODERATE" ? "warn" : "ok";
        log(r.filename + " → " + r.threat_level + " (score " + r.threat_score + "/100)", t);
      });
      getHistory().then((h) => setHistory(h.data.scans || [])).catch(() => {});
    } catch (err) {
      setPhase("error");
      log("ERROR: " + (err.response && err.response.data && err.response.data.error ? err.response.data.error : err.message), "err");
    }
  };

  const handleQuarantine = async (scanId) => {
    try { await quarantineFile(scanId); log("File " + scanId + " quarantined", "warn"); }
    catch (e) { log("Quarantine failed: " + e.message, "err"); }
  };

  const handleDelete = async (scanId) => {
    try {
      await deleteScan(scanId);
      setResults((r) => r.filter((x) => x.scan_id !== scanId));
      if (activeResult && activeResult.scan_id === scanId) setActive(null);
      log("Scan " + scanId + " deleted", "info");
    } catch (e) { log("Delete failed: " + e.message, "err"); }
  };

  const reset = () => {
    setFiles([]); setPhase("idle"); setResults([]);
    setActive(null); setUploadPct(0);
    log("Scanner reset", "info");
  };

  const totalThreats = results.filter((r) => r.threat_level === "HIGH" || r.threat_level === "CRITICAL").length;
  const totalSuspect = results.filter((r) => r.threat_level === "MODERATE").length;
  const totalClean   = results.filter((r) => r.threat_level === "SAFE" || r.threat_level === "LOW").length;
  const avgScore     = results.length ? Math.round(results.reduce((a, b) => a + (b.threat_score || 0), 0) / results.length) : 0;

  const score = activeResult ? activeResult.threat_score : avgScore;
  const level = activeResult ? activeResult.threat_level : (results.length ? "—" : "READY");
  const threatColor = score >= 75 ? "#ff2244" : score >= 50 ? "#ff6600" : score >= 25 ? "#ffcc00" : "#00ff88";

  return (
    <div className="root">
      <div className="grid-bg" />
      <div className="scanline" />
      <div className="content">

        {/* HEADER */}
        <header className="header">
          <div className="logo">
            <div className="logo-hex">🛡️</div>
            <div>
              <div className="logo-title">NEUROVIRUS</div>
              <div className="logo-sub">ADVANCED THREAT INTELLIGENCE PLATFORM</div>
            </div>
          </div>
          <nav className="nav">
            {["scan","history","status"].map((t) => (
              <button key={t} className={"nav-btn" + (tab === t ? " active" : "")} onClick={() => setTab(t)}>
                {t === "scan" ? "⚡ SCAN" : t === "history" ? "📋 HISTORY" : "📡 ENGINE"}
              </button>
            ))}
          </nav>
          <div className="header-right">
            <div className="status-dot" />
            <span className="mono-sm">{engineStatus && engineStatus.error ? "BACKEND OFFLINE" : "BACKEND ONLINE"} · {getNow()}</span>
          </div>
        </header>

        {/* QUICK STATS */}
        <div className="qs-row">
          <div className="qs-card qs-cyan"><span className="qs-icon">🗂️</span><div className="qs-num c-cyan">{results.length}</div><div className="qs-label">SCANNED</div></div>
          <div className="qs-card qs-red"><span className="qs-icon">☣️</span><div className="qs-num c-red">{totalThreats}</div><div className="qs-label">THREATS</div></div>
          <div className="qs-card qs-yellow"><span className="qs-icon">⚠️</span><div className="qs-num c-yellow">{totalSuspect}</div><div className="qs-label">SUSPICIOUS</div></div>
          <div className="qs-card qs-green"><span className="qs-icon">✅</span><div className="qs-num c-green">{totalClean}</div><div className="qs-label">CLEAN</div></div>
        </div>

        {/* SCAN TAB */}
        {tab === "scan" && (
          <div className="scan-grid">

            {/* LEFT */}
            <div className="col-left">
              <div className="panel">
                <div className="panel-hdr"><span>📁</span><span className="panel-title">TARGET ACQUISITION</span></div>
                <div className="panel-body">
                  <div className={"dropzone" + (dragOver ? " drag" : "")}
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files); }}
                    onClick={() => fileRef.current.click()}>
                    <input ref={fileRef} type="file" multiple style={{display:"none"}} onChange={(e) => handleFiles(e.target.files)} />
                    <div className="dz-icon">📡</div>
                    <div className="dz-title">DROP FILES OR CLICK TO UPLOAD</div>
                    <div className="dz-sub">Any file type · Max 512 MB</div>
                    <div className="dz-tags">
                      {["exe","dll","pdf","doc","zip","img","apk","js","py","iso"].map((t) => (
                        <span key={t} className="tag">.{t}</span>
                      ))}
                    </div>
                  </div>

                  {files.length > 0 && (
                    <div className="file-queue">
                      <div className="section-label">QUEUED FILES</div>
                      {files.map((f, i) => (
                        <div key={i} className="fq-row">
                          <span>{f.name.match(/\.(exe|dll|bat|cmd|msi|sh)$/i) ? "⚙️" : f.name.match(/\.(jpg|jpeg|png|gif|bmp|svg|webp)$/i) ? "🖼️" : f.name.match(/\.(pdf|doc|docx)$/i) ? "📄" : f.name.match(/\.(zip|rar|7z|tar|gz)$/i) ? "🗜️" : "📄"}</span>
                          <span className="fq-name">{f.name}</span>
                          <span className="fq-size mono-sm">{fmt(f.size)}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {phase === "uploading" && (
                    <div className="upload-bar">
                      <div className="section-label">UPLOADING {uploadPct}%</div>
                      <div className="bar-bg"><div className="bar-fill" style={{width: uploadPct + "%", background: "var(--cyan)"}} /></div>
                    </div>
                  )}

                  <button className="scan-btn"
                    onClick={phase === "done" || phase === "error" ? reset : startScan}
                    disabled={phase === "uploading" || phase === "scanning" || !files.length}>
                    {phase === "uploading" ? "⬆ UPLOADING..." : phase === "scanning" ? "◉ ANALYZING..." : phase === "done" || phase === "error" ? "↺ RESET" : "▶ INITIATE SCAN"}
                  </button>
                </div>
              </div>

              {activeResult && (
                <div className="panel">
                  <div className="panel-hdr"><span>🔎</span><span className="panel-title">FILE DETAILS</span></div>
                  <div className="panel-body">
                    <div className="meta-grid">
                      {[["NAME", activeResult.filename],["SIZE", fmt(activeResult.file_size)],["TYPE", activeResult.file_type_magic],["EXT", "." + activeResult.file_extension],["ENTROPY", (activeResult.entropy || 0).toFixed(3) + "/8.0"],["TIME", (activeResult.scan_duration_ms || 0) + "ms"]].map(function(item) {
                        return (
                          <div key={item[0]} className="meta-row">
                            <span className="meta-key">{item[0]}</span>
                            <span className="meta-val">{item[1]}</span>
                          </div>
                        );
                      })}
                    </div>
                    <div className="section-label mt">HASHES</div>
                    {["md5","sha1","sha256"].map((h) => (
                      <div key={h} className="hash-row">
                        <span className="hash-key">{h.toUpperCase()}</span>
                        <span className="hash-val">{activeResult.hashes && activeResult.hashes[h]}</span>
                      </div>
                    ))}
                    <div className="btn-row mt">
                      <button className="action-btn warn" onClick={() => handleQuarantine(activeResult.scan_id)}>🔒 QUARANTINE</button>
                      <button className="action-btn danger" onClick={() => handleDelete(activeResult.scan_id)}>🗑 DELETE</button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* CENTER */}
            <div className="col-center">
              <div className="panel">
                <div className="panel-hdr"><span>☢️</span><span className="panel-title">THREAT INDEX</span></div>
                <div className="panel-body center">
                  <div className="gauge-wrap">
                    <div className="gauge-ring" style={{background: "conic-gradient(" + threatColor + " " + score + "%, #0a2a3a " + score + "%)"}}>
                      <div className="gauge-inner">
                        <div className="gauge-score" style={{color: threatColor, textShadow: "0 0 20px " + threatColor}}>{score}</div>
                        <div className="gauge-label" style={{color: threatColor}}>{level}</div>
                      </div>
                    </div>
                  </div>
                  {results.length > 1 && (
                    <div className="file-tabs">
                      {results.map((r) => (
                        <button key={r.scan_id}
                          className={"file-tab" + (activeResult && activeResult.scan_id === r.scan_id ? " active" : "")}
                          onClick={() => setActive(r)}>
                          {r.filename && r.filename.slice(0, 18)}{r.filename && r.filename.length > 18 ? "…" : ""}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="panel">
                <div className="panel-hdr"><span>🌐</span><span className="panel-title">VIRUSTOTAL</span></div>
                <div className="panel-body">
                  {!activeResult || !activeResult.virustotal ? (
                    <div className="mono-sm dim">Run a scan first</div>
                  ) : activeResult.virustotal.status === "NO_API_KEY" ? (
                    <div className="mono-sm" style={{color:"var(--yellow)"}}>⚠ Set VIRUSTOTAL_API_KEY in .env</div>
                  ) : activeResult.virustotal.status === "NOT_FOUND" ? (
                    <div className="mono-sm c-green">✓ Hash not found in VirusTotal database (clean)</div>
                  ) : activeResult.virustotal.status === "FOUND" ? (
                    <div>
                      <div className="vt-summary">
                        <span className={"vt-score " + (activeResult.virustotal.detections > 0 ? "c-red" : "c-green")}>
                          {activeResult.virustotal.detections}/{activeResult.virustotal.total_engines}
                        </span>
                        <span className="mono-sm dim"> engines flagged</span>
                      </div>
                      {activeResult.virustotal.link && (
                        <a href={activeResult.virustotal.link} target="_blank" rel="noreferrer" className="vt-link">↗ View on VirusTotal</a>
                      )}
                    </div>
                  ) : (
                    <div className="mono-sm dim">{activeResult.virustotal.status}</div>
                  )}
                </div>
              </div>

              <div className="panel">
                <div className="panel-hdr"><span>🔬</span><span className="panel-title">ENGINE RESULTS</span></div>
                <div className="panel-body">
                  <div className="engine-row">
                    <span className="engine-label">ClamAV</span>
                    <span className={"engine-badge " + (activeResult && activeResult.clamav && activeResult.clamav.status === "FOUND" ? "badge-critical" : activeResult && activeResult.clamav && activeResult.clamav.status === "OK" ? "badge-clean" : "badge-info")}>
                      {activeResult && activeResult.clamav ? activeResult.clamav.status : "—"}
                      {activeResult && activeResult.clamav && activeResult.clamav.signature ? " · " + activeResult.clamav.signature : ""}
                    </span>
                  </div>
                  <div className="engine-row">
                    <span className="engine-label">YARA Rules</span>
                    <span className={"engine-badge " + ((activeResult && activeResult.yara_matches && activeResult.yara_matches.length > 0) ? "badge-high" : "badge-clean")}>
                      {activeResult && activeResult.yara_matches ? activeResult.yara_matches.length : 0} MATCHES
                    </span>
                  </div>
                  {activeResult && activeResult.yara_matches && activeResult.yara_matches.map((m, i) => (
                    <div key={i} className="yara-match">
                      <span className="badge badge-high mono-sm">YARA</span>
                      <span className="mono-sm">{m.rule}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* RIGHT */}
            <div className="col-right">
              <div className="panel" style={{flex:1}}>
                <div className="panel-hdr">
                  <span>🚨</span>
                  <span className="panel-title">DETECTIONS</span>
                  <span className="panel-count">{activeResult && activeResult.findings ? activeResult.findings.length : 0}</span>
                </div>
                <div className="panel-body no-pad">
                  {!activeResult ? (
                    <div className="empty-state"><div className="empty-icon">🛡️</div><div className="mono-sm dim">AWAITING SCAN...</div></div>
                  ) : (
                    <div className="findings-list">
                      {(activeResult.findings || []).slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).map((f, i) => (
                        <div key={i} className={"finding sev-border-" + f.severity}>
                          <div className={"sev-dot sev-dot-" + f.severity} />
                          <div className="finding-content">
                            <div className="finding-name">{f.name}</div>
                            <div className="finding-detail">{f.detail}</div>
                            <div className="finding-meta">
                              <span className={"badge badge-" + f.severity}>{f.severity.toUpperCase()}</span>
                              <span className="badge badge-info">{f.category}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {activeResult && activeResult.network_indicators && activeResult.network_indicators.length > 0 && (
                <div className="panel">
                  <div className="panel-hdr"><span>📡</span><span className="panel-title">NETWORK IOCs</span></div>
                  <div className="panel-body no-pad">
                    {activeResult.network_indicators.slice(0,8).map((n, i) => (
                      <div key={i} className="net-row">
                        <span className={"badge badge-" + n.severity}>{n.type}</span>
                        <span className="net-val mono-sm">{n.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeResult && activeResult.suspicious_strings && activeResult.suspicious_strings.length > 0 && (
                <div className="panel">
                  <div className="panel-hdr"><span>🔤</span><span className="panel-title">SUSPICIOUS STRINGS</span></div>
                  <div className="panel-body no-pad">
                    {activeResult.suspicious_strings.map((s, i) => (
                      <div key={i} className="str-row">
                        <span className={"badge badge-" + s.severity}>{s.severity.toUpperCase()}</span>
                        <span className="mono-sm">{s.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TERMINAL */}
        {tab === "scan" && (
          <div className="panel mt">
            <div className="panel-hdr"><span>⌨️</span><span className="panel-title">SCAN CONSOLE</span></div>
            <div className="terminal" ref={termRef}>
              {logs.map((l, i) => (
                <div key={i} className={"log-line log-" + l.type}>
                  <span className="log-ts">[{l.ts}]</span> {l.msg}
                </div>
              ))}
              {phase === "scanning" && <span className="cursor" />}
            </div>
          </div>
        )}

        {/* HISTORY TAB */}
        {tab === "history" && (
          <div className="panel mt">
            <div className="panel-hdr"><span>📋</span><span className="panel-title">SCAN HISTORY</span></div>
            <div className="panel-body">
              {history.length === 0 ? (
                <div className="empty-state"><div className="empty-icon">📭</div><div className="mono-sm dim">No scan history yet</div></div>
              ) : (
                <table className="hist-table">
                  <thead><tr><th>TIMESTAMP</th><th>FILE</th><th>SIZE</th><th>SCORE</th><th>LEVEL</th><th>FINDINGS</th></tr></thead>
                  <tbody>
                    {history.slice().reverse().map((h) => (
                      <tr key={h.scan_id}>
                        <td className="mono-sm dim">{h.timestamp && h.timestamp.slice(0,19).replace("T"," ")}</td>
                        <td className="mono-sm">{h.filename}</td>
                        <td className="mono-sm dim">{fmt(h.file_size)}</td>
                        <td className="mono-sm c-green">{h.threat_score}</td>
                        <td><span className={"badge badge-" + (h.threat_level && h.threat_level.toLowerCase())}>{h.threat_level}</span></td>
                        <td className="mono-sm dim">{h.finding_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* STATUS TAB */}
        {tab === "status" && (
          <div className="status-grid mt">
            {[
              {name:"ClamAV", icon:"🦠", data: engineStatus && engineStatus.clamav},
              {name:"YARA Engine", icon:"🧬", data: engineStatus && engineStatus.yara},
              {name:"VirusTotal API", icon:"🌐", data: engineStatus && engineStatus.virustotal},
            ].map(function(item) {
              return (
                <div key={item.name} className="panel">
                  <div className="panel-hdr"><span>{item.icon}</span><span className="panel-title">{item.name}</span></div>
                  <div className="panel-body">
                    <div className={"big-badge " + (item.data && item.data.available ? "badge-clean" : "badge-critical")}>
                      {item.data && item.data.available ? "ONLINE" : "OFFLINE"}
                    </div>
                    {item.data && Object.entries(item.data).filter(function(e) { return e[0] !== "available"; }).map(function(e) {
                      return (
                        <div key={e[0]} className="meta-row mt-sm">
                          <span className="meta-key">{e[0].replace(/_/g," ").toUpperCase()}</span>
                          <span className="meta-val mono-sm">{String(e[1])}</span>
                        </div>
                      );
                    })}
                    {!item.data && <div className="mono-sm dim">Checking...</div>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <footer className="footer">NEUROVIRUS · FLASK + CLAMAV + YARA + VIRUSTOTAL · v3.14.1</footer>
      </div>
    </div>
  );
}
