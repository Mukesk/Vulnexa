import React, { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
// import scanData from "./scanResults.json";

type Severity = "Critical" | "High" | "Medium" | "Low";
type ScanStatus = "IDLE" | "SCANNING" | "COMPLETED";

type Occurrence = {
  filename: string;
  line: number;
  severity: Severity;
};

type VulnerabilityCategory = {
  category: string;
  count: number;
  occurrences: Occurrence[];
};

type ThemeMode = "dark" | "ultra" | "red";

const severityWeights: Record<Severity, number> = {
  Critical: 5,
  High: 3,
  Medium: 2,
  Low: 1
};

const severityColors: Record<Severity, string> = {
  Critical: "from-red-500 to-rose-600",
  High: "from-orange-400 to-amber-500",
  Medium: "from-yellow-400 to-lime-400",
  Low: "from-emerald-400 to-teal-400"
};

const severityBadgeColors: Record<Severity, string> = {
  Critical: "bg-red-500/20 text-red-300 border-red-500/60",
  High: "bg-orange-500/20 text-orange-300 border-orange-500/60",
  Medium: "bg-yellow-400/20 text-yellow-200 border-yellow-400/60",
  Low: "bg-emerald-500/20 text-emerald-300 border-emerald-500/60"
};

const themeClasses: Record<ThemeMode, string> = {
  dark: "bg-cyber-bg text-slate-100",
  ultra: "bg-black text-slate-100",
  red: "bg-gradient-to-b from-black via-red-950/20 to-black text-rose-100"
};

const themeAccentColors: Record<ThemeMode, { primary: string; secondary: string }> = {
  dark: { primary: "cyber-cyan", secondary: "cyber-purple" },
  ultra: { primary: "cyber-purple", secondary: "cyber-cyan" },
  red: { primary: "cyber-red", secondary: "rose-400" }
};

const statusLabels: Record<ScanStatus, string> = {
  IDLE: "Idle",
  SCANNING: "Scanning…",
  COMPLETED: "Completed"
};

function isValidGitHubUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return (
      (u.hostname === "github.com" ||
        u.hostname.endsWith(".github.com")) &&
      u.pathname.split("/").filter(Boolean).length >= 2
    );
  } catch {
    return false;
  }
}

function computeRiskScore(data: VulnerabilityCategory[]): number {
  let weighted = 0;
  let total = 0;
  data.forEach(cat => {
    cat.occurrences.forEach(o => {
      weighted += severityWeights[o.severity];
      total += 1;
    });
  });
  if (!total) return 0;
  const maxPerFinding = 5;
  const normalized = (weighted / (total * maxPerFinding)) * 100;
  return Math.min(100, Math.round(normalized));
}

function getRiskLabel(score: number): string {
  if (score < 25) return "Low Risk";
  if (score < 50) return "Moderate Risk";
  if (score < 75) return "High Risk";
  return "Critical Risk";
}

function getRiskColor(score: number): string {
  if (score < 25) return "text-emerald-400";
  if (score < 50) return "text-yellow-400";
  if (score < 75) return "text-orange-400";
  return "text-red-400";
}

function aggregateSeverityCounts(data: VulnerabilityCategory[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const cat of data) {
    for (const occ of cat.occurrences) {
      counts[occ.severity] += 1;
    }
  }
  return counts;
}

function getDominantSeverity(cat: VulnerabilityCategory): Severity | null {
  if (!cat.occurrences.length) return null;
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  cat.occurrences.forEach(o => (counts[o.severity] += 1));
  return (Object.entries(counts).sort((a, b) => b[1] - a[1])[0]![0] as Severity) || null;
}

function buildFlatVulnList(
  data: VulnerabilityCategory[],
  categoryFilter: string | null
): (Occurrence & { category: string })[] {
  const rows: (Occurrence & { category: string })[] = [];
  for (const cat of data) {
    if (categoryFilter && cat.category !== categoryFilter) continue;
    for (const occ of cat.occurrences) {
      rows.push({ ...occ, category: cat.category });
    }
  }
  return rows;
}

function getHighestRiskCategory(data: VulnerabilityCategory[]): string | null {
  if (!data.length) return null;
  let best = data[0];
  let bestScore = -1;
  for (const cat of data) {
    const total = cat.occurrences.reduce((acc, o) => acc + severityWeights[o.severity], 0);
    if (total > bestScore) {
      bestScore = total;
      best = cat;
    }
  }
  return best.category;
}

function App() {
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [status, setStatus] = useState<ScanStatus>("IDLE");
  const [repoUrl, setRepoUrl] = useState("");
  const [data, setData] = useState<VulnerabilityCategory[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "All">("All");
  const [selectedVuln, setSelectedVuln] = useState<{
    category: string;
    occurrence: Occurrence;
  } | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const [logLines, setLogLines] = useState<string[]>([
    "[+] VULNEXA security scanner initialized.",
    "[*] Awaiting repository URL input…"
  ]);
  const [exportingType, setExportingType] = useState<"JSON" | "PDF" | null>(null);

  // Load static scan data after "scan" completes
  //   useEffect(() => {
  //     if (status !== "COMPLETED") return;
  //     setData(scanData as VulnerabilityCategory[]);
  //   }, [status]);

  const flatVulns = useMemo(
    () => buildFlatVulnList(data, categoryFilter),
    [data, categoryFilter]
  );

  const filteredVulns = useMemo(() => {
    return flatVulns
      .filter(vuln => {
        if (severityFilter !== "All" && vuln.severity !== severityFilter) return false;
        if (!search.trim()) return true;
        const query = search.toLowerCase();
        return (
          vuln.category.toLowerCase().includes(query) ||
          vuln.filename.toLowerCase().includes(query) ||
          `${vuln.line}`.includes(query)
        );
      })
      .sort((a, b) => severityWeights[b.severity] - severityWeights[a.severity]);
  }, [flatVulns, severityFilter, search]);

  const riskScore = useMemo(() => computeRiskScore(data), [data]);
  const riskLabel = useMemo(() => getRiskLabel(riskScore), [riskScore]);
  const severityCounts = useMemo(() => aggregateSeverityCounts(data), [data]);

  const totalVulns = useMemo(
    () => data.reduce((acc, cat) => acc + cat.occurrences.length, 0),
    [data]
  );
  const highestRiskArea = useMemo(() => getHighestRiskCategory(data), [data]);

  // Auto-hide toast
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(timer);
  }, [toast]);

  function addLogLine(line: string) {
    setLogLines(prev => [...prev.slice(-50), `${new Date().toISOString().split('T')[1].split('.')[0]}  ${line}`]);
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim() || !isValidGitHubUrl(repoUrl.trim())) {
      setToast({ message: "Please provide a valid GitHub repository URL.", type: "error" });
      return;
    }
    setStatus("SCANNING");
    setData([]);
    setCategoryFilter(null);
    setLogLines([]); // Clear previous logs

    addLogLine(`[*] Queued scan for ${repoUrl.trim()}`);
    addLogLine("[*] Connecting to Vulnexa Backend...");

    try {
      const response = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl.trim() })
      });

      if (!response.ok) {
        let errorMsg = `Scan failed: ${response.statusText}`;
        try {
          const errorData = await response.json();
          if (errorData.detail) {
            errorMsg = errorData.detail;
          }
        } catch (e) {
          // ignore json parse error
        }
        throw new Error(errorMsg);
      }

      const result = await response.json();

      setData(result.vulnerabilities);
      setStatus("COMPLETED");
      addLogLine(`[+] Scan completed. Risk Score: ${result.summary.riskScore}`);
      setToast({ message: "Security scan completed successfully.", type: "success" });

    } catch (error) {
      console.error(error);
      setStatus("IDLE");
      const message = error instanceof Error ? error.message : "Unknown error";
      addLogLine(`[!] Error: ${message}`);
      setToast({ message: message, type: "error" });
    }
  }

  function handleExportJson() {
    if (!data.length) {
      setToast({ message: "No scan data available for export.", type: "error" });
      return;
    }
    setExportingType("JSON");
    const payload = {
      repository: repoUrl,
      scanTime: new Date().toISOString(),
      vulnerabilities: data,
      summary: {
        totalVulns,
        riskScore,
        riskLevel: riskLabel,
        highestRiskArea
      }
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vulnexa-security-report.json";
    a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => {
      setExportingType(null);
      setToast({ message: "JSON security report exported successfully.", type: "success" });
      addLogLine("[+] JSON report exported to downloads.");
    }, 1200);
  }

  function handleExportPdf() {
    if (!data.length) {
      setToast({ message: "No scan data available for export.", type: "error" });
      return;
    }
    setExportingType("PDF");
    addLogLine("[*] Generating comprehensive PDF report…");
    setTimeout(() => {
      setExportingType(null);
      setToast({ message: "PDF export simulation completed (integrate with backend for real PDF generation).", type: "success" });
      addLogLine("[+] PDF report generation simulated successfully.");
    }, 2000);
  }

  const themeAccent = themeAccentColors[theme];

  return (
    <div className={`min-h-screen ${themeClasses[theme]} relative overflow-hidden`}>
      {/* Background Effects */}
      <div className="matrix-bg" />
      <div className="cyber-grid" />
      <div
        className={`pointer-events-none fixed inset-0 mix-blend-screen opacity-30 blur-3xl ${theme === "red"
          ? "bg-[radial-gradient(circle_at_top,_rgba(248,113,113,0.4),_transparent_60%)]"
          : theme === "ultra"
            ? "bg-[radial-gradient(circle_at_top,_rgba(177,88,255,0.35),_transparent_60%)]"
            : "bg-[radial-gradient(circle_at_top,_rgba(34,227,255,0.3),_transparent_60%)]"
          }`}
      />

      <div className="relative z-10 flex min-h-screen flex-col">
        {/* Navigation Header */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-cyber-border/60 bg-black/50 backdrop-blur-md">
          <div className="flex items-center gap-4">
            {/* Logo */}
            <div className="relative h-10 w-10 rounded-xl bg-gradient-to-br from-cyber-red via-cyber-purple to-cyber-cyan shadow-neon-cyan flex items-center justify-center">
              <span className="text-sm font-black tracking-widest text-white">VX</span>
              <span className="absolute inset-0 rounded-xl border border-white/20" />
            </div>

            {/* Title */}
            <div>
              <h1 className="text-xl font-bold tracking-[0.25em] uppercase gradient-text">
                VULNEXA
              </h1>
              <p className="text-xs text-slate-400">
                See the <span className="text-cyber-red">Attack</span>. Fix the <span className="text-cyber-cyan">Code</span>.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            {/* Status Indicator */}
            <div className="flex items-center gap-3 rounded-full border border-cyber-border/70 bg-slate-900/60 px-4 py-2 text-sm">
              <span
                className={`h-3 w-3 rounded-full ${status === "SCANNING"
                  ? `bg-${themeAccent.primary} status-pulse`
                  : status === "COMPLETED"
                    ? "bg-emerald-400 shadow-neon-cyan"
                    : "bg-slate-500"
                  }`}
              />
              <span className="tracking-wide uppercase text-slate-300 font-semibold">
                {statusLabels[status]}
              </span>
            </div>

            {/* Theme Switcher */}
            <div className="glass-panel flex items-center gap-1 px-2 py-2">
              {(["dark", "ultra", "red"] as ThemeMode[]).map(mode => (
                <button
                  key={mode}
                  onClick={() => setTheme(mode)}
                  className={`relative flex items-center gap-2 rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-wide transition-all ${theme === mode
                    ? "bg-gradient-to-r from-cyber-red/60 via-cyber-purple/60 to-cyber-cyan/60 text-white shadow-neon-cyan"
                    : "text-slate-400 hover:text-slate-100"
                    }`}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${mode === "dark"
                      ? "bg-cyber-cyan"
                      : mode === "ultra"
                        ? "bg-cyber-purple"
                        : "bg-cyber-red"
                      }`}
                  />
                  {mode === "dark" && "Dark"}
                  {mode === "ultra" && "Ultra"}
                  {mode === "red" && "Red Team"}
                </button>
              ))}
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 px-6 py-6 lg:px-10 lg:py-8">
          <div className="grid gap-8 xl:grid-cols-[1fr_400px]">
            {/* Left Column - Main Dashboard */}
            <div className="space-y-8">
              {/* Landing/Scan Section */}
              <section className="glass-panel p-6 lg:p-8 relative overflow-hidden">
                <div className="absolute inset-0 pointer-events-none bg-gradient-to-br from-cyber-red/5 via-transparent to-cyber-cyan/5" />
                <div className="relative">
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
                    <div className="max-w-2xl">
                      <h2 className="text-2xl font-bold tracking-[0.15em] uppercase text-slate-100 mb-3">
                        Repository Security Analysis
                      </h2>
                      <p className="text-sm text-slate-400 leading-relaxed">
                        Submit a GitHub repository URL to initiate a comprehensive security scan. VULNEXA will
                        analyze your codebase for vulnerabilities, security misconfigurations, and potential attack vectors.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleScan} className="mt-8 space-y-4">
                    <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
                      <div>
                        <label className="block text-xs font-semibold tracking-wide uppercase text-slate-400 mb-2">
                          GitHub Repository URL
                        </label>
                        <input
                          type="text"
                          value={repoUrl}
                          onChange={(e) => setRepoUrl(e.target.value)}
                          placeholder="https://github.com/owner/repository"
                          className="w-full px-4 py-3 bg-slate-900/60 border border-cyber-border rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-cyan focus:shadow-neon-cyan transition-all"
                          disabled={status === "SCANNING"}
                        />
                      </div>
                      <div className="flex items-end">
                        <button
                          type="submit"
                          disabled={status === "SCANNING"}
                          className="btn-neon disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <span className="flex items-center gap-2">
                            {status === "SCANNING" ? (
                              <>
                                <div className="spinner h-4 w-4" />
                                Scanning
                              </>
                            ) : (
                              "Scan Repository"
                            )}
                          </span>
                        </button>
                      </div>
                    </div>
                  </form>
                </div>
              </section>

              {/* Dashboard Overview - Only show if scan completed */}
              {status === "COMPLETED" && data.length > 0 && (
                <>
                  {/* Risk Score and Heatmap */}
                  <section className="grid gap-6 lg:grid-cols-2">
                    {/* Risk Score Gauge */}
                    <div className="glass-panel p-6 hover-glow">
                      <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200 mb-6">
                        Risk Score Analysis
                      </h3>
                      <div className="flex items-center justify-center">
                        <div className="relative">
                          <svg className="transform -rotate-90 h-32 w-32">
                            <circle
                              cx="64"
                              cy="64"
                              r="56"
                              stroke="rgba(148, 163, 184, 0.2)"
                              strokeWidth="8"
                              fill="transparent"
                            />
                            <circle
                              cx="64"
                              cy="64"
                              r="56"
                              stroke="url(#riskGradient)"
                              strokeWidth="8"
                              fill="transparent"
                              strokeDasharray={`${(riskScore / 100) * 351.86} 351.86`}
                              strokeLinecap="round"
                              className="transition-all duration-1000"
                            />
                            <defs>
                              <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stopColor="#22e3ff" />
                                <stop offset="50%" stopColor="#ff3366" />
                                <stop offset="100%" stopColor="#b158ff" />
                              </linearGradient>
                            </defs>
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className={`text-3xl font-bold ${getRiskColor(riskScore)}`}>
                              {riskScore}
                            </span>
                            <span className="text-xs uppercase tracking-wide text-slate-400">Score</span>
                          </div>
                        </div>
                      </div>
                      <div className="text-center mt-4">
                        <p className={`text-lg font-semibold ${getRiskColor(riskScore)}`}>
                          {riskLabel}
                        </p>
                        <p className="text-xs text-slate-400 mt-1">
                          Based on {totalVulns} vulnerabilities detected
                        </p>
                      </div>
                    </div>

                    {/* Severity Heatmap */}
                    <div className="glass-panel p-6 hover-glow">
                      <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200 mb-6">
                        Severity Distribution
                      </h3>
                      <div className="space-y-4">
                        {(Object.entries(severityCounts) as [Severity, number][]).map(([severity, count]) => {
                          const maxCount = Math.max(...Object.values(severityCounts));
                          const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;

                          return (
                            <div key={severity} className="flex items-center gap-4">
                              <div className="w-20 text-sm font-semibold text-slate-300">
                                {severity}
                              </div>
                              <div className="flex-1 bg-slate-800 rounded-full h-4 relative overflow-hidden">
                                <div
                                  className={`h-full bg-gradient-to-r ${severityColors[severity]} rounded-full transition-all duration-1000 shadow-lg`}
                                  style={{ width: `${percentage}%` }}
                                />
                              </div>
                              <div className="w-8 text-sm font-bold text-slate-200 text-right">
                                {count}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </section>

                  {/* Vulnerability Categories */}
                  <section className="glass-panel p-6 hover-glow">
                    <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200 mb-6">
                      Vulnerability Categories
                    </h3>
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      {data.map((cat) => {
                        const dominant = getDominantSeverity(cat);
                        return (
                          <motion.button
                            key={cat.category}
                            onClick={() => setCategoryFilter(cat.category === categoryFilter ? null : cat.category)}
                            className={`p-4 rounded-xl border transition-all text-left hover:scale-[1.02] ${categoryFilter === cat.category
                              ? "border-cyber-cyan bg-cyber-cyan/10 shadow-neon-cyan"
                              : "border-cyber-border bg-slate-800/40 hover:border-cyber-purple"
                              }`}
                            whileHover={{ y: -2 }}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-sm font-semibold text-slate-200">
                                {cat.category}
                              </span>
                              {dominant && (
                                <span className={`px-2 py-1 rounded text-xs border ${severityBadgeColors[dominant]}`}>
                                  {dominant}
                                </span>
                              )}
                            </div>
                            <div className="text-2xl font-bold text-cyber-cyan">
                              {cat.count}
                            </div>
                            <div className="text-xs text-slate-400">
                              {cat.count === 1 ? "vulnerability" : "vulnerabilities"}
                            </div>
                          </motion.button>
                        );
                      })}
                    </div>
                    {categoryFilter && (
                      <div className="mt-4 px-4 py-2 bg-cyber-cyan/10 border border-cyber-cyan/30 rounded-lg">
                        <p className="text-sm text-cyber-cyan">
                          Filtering by: <span className="font-semibold">{categoryFilter}</span>
                          <button
                            onClick={() => setCategoryFilter(null)}
                            className="ml-3 text-xs hover:underline"
                          >
                            Clear filter
                          </button>
                        </p>
                      </div>
                    )}
                  </section>

                  {/* Vulnerabilities Table */}
                  <section className="glass-panel p-6 hover-glow">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
                      <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200">
                        Vulnerability Details
                      </h3>
                      <div className="flex flex-col sm:flex-row gap-3">
                        <input
                          type="text"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          placeholder="Search vulnerabilities..."
                          className="px-3 py-2 bg-slate-800/60 border border-cyber-border rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-cyan"
                        />
                        <select
                          value={severityFilter}
                          onChange={(e) => setSeverityFilter(e.target.value as Severity | "All")}
                          className="px-3 py-2 bg-slate-800/60 border border-cyber-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-cyber-cyan"
                        >
                          <option value="All">All Severities</option>
                          <option value="Critical">Critical</option>
                          <option value="High">High</option>
                          <option value="Medium">Medium</option>
                          <option value="Low">Low</option>
                        </select>
                      </div>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-cyber-border">
                            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wide text-slate-400">
                              Category
                            </th>
                            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wide text-slate-400">
                              File
                            </th>
                            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wide text-slate-400">
                              Line
                            </th>
                            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wide text-slate-400">
                              Severity
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredVulns.map((vuln, index) => (
                            <motion.tr
                              key={`${vuln.category}-${vuln.filename}-${vuln.line}`}
                              initial={{ opacity: 0, y: 20 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: index * 0.05 }}
                              onClick={() => setSelectedVuln({ category: vuln.category, occurrence: vuln })}
                              className="border-b border-cyber-border/30 hover:bg-slate-800/30 cursor-pointer transition-all"
                            >
                              <td className="py-3 px-4 text-sm text-slate-300">
                                {vuln.category}
                              </td>
                              <td className="py-3 px-4 text-sm text-slate-300 font-mono">
                                {vuln.filename}
                              </td>
                              <td className="py-3 px-4 text-sm text-slate-300 font-mono">
                                {vuln.line}
                              </td>
                              <td className="py-3 px-4">
                                <span className={`px-2 py-1 rounded text-xs border ${severityBadgeColors[vuln.severity]}`}>
                                  {vuln.severity}
                                </span>
                              </td>
                            </motion.tr>
                          ))}
                        </tbody>
                      </table>
                      {filteredVulns.length === 0 && (
                        <div className="text-center py-8 text-slate-400">
                          No vulnerabilities match your current filters.
                        </div>
                      )}
                    </div>
                  </section>
                </>
              )}
            </div>

            {/* Right Column - Sidebar */}
            <aside className="space-y-6">
              {/* Report Summary */}
              {status === "COMPLETED" && data.length > 0 && (
                <div className="glass-panel p-6 hover-glow">
                  <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200 mb-6">
                    Security Report
                  </h3>
                  <div className="space-y-4 mb-6">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Total Vulnerabilities</span>
                      <span className="text-sm font-semibold text-slate-200">{totalVulns}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Risk Score</span>
                      <span className={`text-sm font-semibold ${getRiskColor(riskScore)}`}>{riskScore}/100</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Highest Risk Area</span>
                      <span className="text-sm font-semibold text-slate-200">{highestRiskArea}</span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <button
                      onClick={handleExportJson}
                      disabled={exportingType === "JSON"}
                      className="w-full px-4 py-3 bg-slate-800/60 border border-cyber-border rounded-lg text-sm font-semibold text-slate-200 hover:border-cyber-cyan hover:bg-slate-700/60 transition-all disabled:opacity-50"
                    >
                      {exportingType === "JSON" ? (
                        <span className="flex items-center justify-center gap-2">
                          <div className="spinner h-4 w-4" />
                          Exporting JSON...
                        </span>
                      ) : (
                        "Export JSON Report"
                      )}
                    </button>
                    <button
                      onClick={handleExportPdf}
                      disabled={exportingType === "PDF"}
                      className="w-full px-4 py-3 bg-slate-800/60 border border-cyber-border rounded-lg text-sm font-semibold text-slate-200 hover:border-cyber-purple hover:bg-slate-700/60 transition-all disabled:opacity-50"
                    >
                      {exportingType === "PDF" ? (
                        <span className="flex items-center justify-center gap-2">
                          <div className="spinner h-4 w-4" />
                          Generating PDF...
                        </span>
                      ) : (
                        "Export PDF Report (Mock)"
                      )}
                    </button>
                  </div>
                </div>
              )}

              {/* Terminal Log */}
              <div className="glass-panel p-6 hover-glow">
                <h3 className="text-lg font-semibold uppercase tracking-wide text-slate-200 mb-4">
                  Activity Log
                </h3>
                <div className="bg-black/60 rounded-lg p-4 h-64 overflow-y-auto">
                  <div className="space-y-1 font-mono text-xs">
                    {logLines.map((line, index) => (
                      <motion.div
                        key={index}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`${line.includes("[+]")
                          ? "text-emerald-400"
                          : line.includes("[*]")
                            ? "text-cyber-cyan"
                            : "text-slate-400"
                          }`}
                      >
                        {line}
                      </motion.div>
                    ))}
                  </div>
                </div>
              </div>
            </aside>
          </div>
        </main>
      </div>

      {/* Vulnerability Detail Modal */}
      <AnimatePresence>
        {selectedVuln && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-6 z-50"
            onClick={() => setSelectedVuln(null)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              onClick={(e) => e.stopPropagation()}
              className="glass-panel p-8 max-w-2xl w-full max-h-[80vh] overflow-y-auto border-cyber-cyan shadow-neon-cyan"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-semibold text-slate-100">Vulnerability Details</h3>
                <button
                  onClick={() => setSelectedVuln(null)}
                  className="text-slate-400 hover:text-slate-200 transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                      Category
                    </label>
                    <p className="text-slate-200">{selectedVuln.category}</p>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                      Severity
                    </label>
                    <span className={`px-3 py-1 rounded border ${severityBadgeColors[selectedVuln.occurrence.severity]}`}>
                      {selectedVuln.occurrence.severity}
                    </span>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                    File Location
                  </label>
                  <p className="text-slate-200 font-mono bg-slate-800/60 px-3 py-2 rounded border border-cyber-border">
                    {selectedVuln.occurrence.filename}:{selectedVuln.occurrence.line}
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                    Risk Assessment
                  </label>
                  <p className="text-slate-300 text-sm leading-relaxed">
                    This {selectedVuln.category.toLowerCase()} vulnerability poses a {selectedVuln.occurrence.severity.toLowerCase()}
                    security risk to your application. Immediate remediation is recommended to prevent potential exploitation.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                    Attack Flow
                  </label>
                  <div className="flex items-center gap-4 p-4 bg-slate-800/60 rounded border border-cyber-border">
                    <div className="flex items-center gap-2 text-sm">
                      <div className="px-3 py-1 bg-red-500/20 text-red-300 rounded border border-red-500/60">
                        Source
                      </div>
                      <span className="text-slate-400">→</span>
                      <div className="px-3 py-1 bg-yellow-500/20 text-yellow-300 rounded border border-yellow-500/60">
                        Variable
                      </div>
                      <span className="text-slate-400">→</span>
                      <div className="px-3 py-1 bg-purple-500/20 text-purple-300 rounded border border-purple-500/60">
                        Sink
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">
                    Recommended Fix
                  </label>
                  <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded text-sm text-emerald-200">
                    Implement proper input validation and sanitization. Use parameterized queries and avoid dynamic query construction with user input.
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Toast Notifications */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -100 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -100 }}
            className="fixed top-6 right-6 z-50"
          >
            <div className={`glass-panel px-6 py-4 border-l-4 ${toast.type === "success"
              ? "border-emerald-400 bg-emerald-500/10"
              : "border-red-400 bg-red-500/10"
              }`}>
              <p className={`text-sm font-medium ${toast.type === "success" ? "text-emerald-200" : "text-red-200"
                }`}>
                {toast.message}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default App
