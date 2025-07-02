import React, { useState, useEffect } from "react";
import {
  Container, Typography, Box, TextField, Button, MenuItem, Paper, CircularProgress, Alert,
  AppBar, Toolbar, Divider, Card, CardContent, Tooltip, IconButton
} from "@mui/material";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip as ChartTooltip, ResponsiveContainer, CartesianGrid, Legend } from "recharts";
import Stack from "@mui/material/Stack";
import SecurityIcon from '@mui/icons-material/Security';
import WifiIcon from '@mui/icons-material/Wifi';
import BugReportIcon from '@mui/icons-material/BugReport';
import WebIcon from '@mui/icons-material/Web';
import DownloadIcon from '@mui/icons-material/Download';
import HistoryIcon from '@mui/icons-material/History';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ReportSummary from './components/ReportSummary';
import ReportCharts from './components/ReportCharts';
import ReportDetails from './components/ReportDetails';
import ScanHistory from './components/ScanHistory';
import SystemInfo from './components/SystemInfo';
import ScanAlerts from './components/ScanAlerts';

// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const scanTypes = [
  { value: "full", label: "Full Scan", icon: <SecurityIcon color="primary" /> },
  { value: "ports", label: "Port Scan", icon: <WifiIcon color="primary" /> },
  { value: "cve", label: "CVE Check", icon: <BugReportIcon color="error" /> },
  { value: "web", label: "Web Header Scan", icon: <WebIcon color="secondary" /> },
  { value: "password", label: "Password Audit", icon: <SecurityIcon color="secondary" /> },
  { value: "config", label: "Config Audit", icon: <SecurityIcon color="action" /> },
  { value: "network", label: "Network Discovery", icon: <WifiIcon color="info" /> },
];

const outputTypes = [
  { value: "json", label: "JSON" },
  { value: "html", label: "HTML" }
];

const scanProfiles = [
  { value: 'default', label: 'Default', description: 'Standard security scan' },
  { value: 'aggressive', label: 'Aggressive', description: 'Fast but noisy scan' },
  { value: 'stealth', label: 'Stealth', description: 'Slow but quiet scan' },
  { value: 'vuln', label: 'Vulnerability', description: 'Nmap vuln script scan' }
];

// Helper: Extract summary from JSON report
function getSummary(report: string) {
  try {
    const data = JSON.parse(report);
    // Fallback for port scan key
    const portsArr = data.ports || data.port_results || [];
    return {
      ports: Array.isArray(portsArr) ? portsArr.length : 0,
      cves: data.cves && data.cves[0]?.cve_findings
        ? data.cves[0].cve_findings.filter((f: any) => f.cve_id).length
        : 0,
      web: data.web && data.web.missing ? data.web.missing.length : 0,
      password: data.password && Array.isArray(data.password)
        ? data.password.filter((p: any) => p.status === "fail").length
        : 0,
      config: data.config && data.config.ssh_config
        ? data.config.ssh_config.filter((c: any) => c.status === "fail").length
        : 0,
    };
  } catch {
    return { ports: 0, cves: 0, web: 0, password: 0, config: 0 };
  }
}

// Helper: Extract CVE severity counts for chart
function getCveSeverityData(report: string) {
  try {
    const data = JSON.parse(report);
    const findings = data.cves && data.cves[0]?.cve_findings ? data.cves[0].cve_findings : [];
    const counts: Record<string, number> = {};
    findings.forEach((f: any) => {
      const sev = (f.severity || "UNKNOWN").toUpperCase();
      if (f.cve_id) counts[sev] = (counts[sev] || 0) + 1;
    });
    return Object.entries(counts).map(([severity, count]) => ({ severity, count }));
  } catch {
    return [];
  }
}

// Helper: Extract open ports for chart
function getPortData(report: string) {
  try {
    const data = JSON.parse(report);
    // Fallback for port scan key
    const portsArr = data.ports || data.port_results || [];
    if (!Array.isArray(portsArr)) return [];
    const portCounts: Record<string, number> = {};
    portsArr.forEach((p: any) => {
      const state = (p.state || "unknown").toUpperCase();
      portCounts[state] = (portCounts[state] || 0) + 1;
    });
    return Object.entries(portCounts).map(([state, count]) => ({ state, count }));
  } catch {
    return [];
  }
}

function App() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("full");
  const [output, setOutput] = useState("json");
  const [scanProfile, setScanProfile] = useState("default");
  const [useApi, setUseApi] = useState(false);
  const [timeout, setTimeout] = useState(30);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState("");
  const [error, setError] = useState("");
  const [history, setHistory] = useState<any[]>([]);
  const [scanId, setScanId] = useState<string | null>(null);
  const [reportFilename, setReportFilename] = useState<string | null>(null);
  const [systemInfo, setSystemInfo] = useState<any>({});

  useEffect(() => {
    axios.get(API_BASE_URL + "/system_info")
      .then(res => setSystemInfo(res.data))
      .catch(err => console.error("Failed to fetch system info:", err));
  }, []);

  useEffect(() => {
    axios.get(API_BASE_URL + "/history?format=" + output)
      .then(res => setHistory(res.data.history || []));
  }, [output, report]); // refresh on output type or after scan

  const handleScan = async () => {
    setLoading(true);
    setError("");
    setReport("");
    setScanId(null);
    setReportFilename(null);

    let scanTarget = target;
    if (scanType === "web" && !/^https?:\/\//i.test(scanTarget)) {
      scanTarget = "http://" + scanTarget;
    }

    try {
      const res = await axios.post(API_BASE_URL + "/scan", {
        target: scanTarget, // use the possibly modified target
        scan_type: scanType,
        output,
        scan_profile: scanProfile,
        use_api: useApi,
        timeout
      });
      if (res.data.success && res.data.report) {
        setReport(res.data.report);
        setReportFilename(res.data.filename || null);
        setLoading(false);
      } else {
        setError(res.data.error || "Scan failed.");
        setLoading(false);
      }
    } catch (e: any) {
      console.error("Scan error:", e);
      if (e.response && e.response.data && e.response.data.detail) {
        setError(e.response.data.detail);
      } else if (e.message) {
        setError(e.message);
      } else {
        setError("Scan failed. Please check the console for details.");
      }
      setLoading(false);
    }
  };

  const pollScanStatus = (id: string) => {
    const interval = setInterval(async () => {
      const res = await axios.get(API_BASE_URL + "/scan_status/" + id);
      if (res.data.status === "done") {
        setReport(res.data.result);
        setLoading(false);
        clearInterval(interval);
      } else if (res.data.status === "error") {
        setError(res.data.result || "Scan failed.");
        setLoading(false);
        clearInterval(interval);
      }
      // else: still running, keep polling
    }, 2000); // poll every 2 seconds
  };

const handleScanTypeChange = (event: React.ChangeEvent<HTMLInputElement>) => {
  const selectedType = event.target.value;
  setScanType(selectedType);
  setError(""); // Clear previous errors
};



  // Summary and chart data
  const summary = report ? getSummary(report) : { ports: 0, cves: 0, web: 0, password: 0, config: 0 };
  const cveSeverityData = report ? getCveSeverityData(report) : [];
  const portData = report ? getPortData(report) : [];

  // Add a helper to check if output is HTML
  const isHtmlOutput = output === "html";

  return (
    <>
      {/* AppBar */}
      <AppBar position="static" color="primary" elevation={2}>
        <Toolbar>
          <SecurityIcon sx={{ mr: 1 }} />
          <Typography variant="h6" fontWeight="bold" sx={{ flexGrow: 1 }}>
            SecuScan Web Dashboard
          </Typography>
          <Typography variant="body2" sx={{ opacity: 0.7 }}>
            Security made simple and modular
          </Typography>
        </Toolbar>
      </AppBar>
      <Container maxWidth="md" sx={{ mt: 6 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          {/* Scan Form */}
          <Box display="flex" alignItems="center" mb={2}>
            <SecurityIcon color="primary" sx={{ fontSize: 40, mr: 2 }} />
            <Typography variant="h4" fontWeight="bold">SecuScan Web</Typography>
            <Tooltip title="Learn more about scan types">
              <IconButton
                href="https://github.com/yourusername/SecuScan#scan-types"
                target="_blank"
                rel="noopener noreferrer"
                size="small"
                sx={{ ml: 1 }}
              >
                <InfoOutlinedIcon />
              </IconButton>
            </Tooltip>
          </Box>
          <Typography variant="subtitle1" mb={3}>
            Run vulnerability and configuration scans with a single click.
          </Typography>
          <Box display="flex" gap={2} mb={2} flexWrap="wrap">
            <TextField
              label="Target (IP, Hostname, URL, or Network Range)"
              value={target}
              onChange={e => setTarget(e.target.value)}
              fullWidth
              sx={{ minWidth: 220 }}
              placeholder={
                scanType === 'network' 
                  ? '192.168.1.0/24' 
                  : scanType === 'web' 
                  ? 'https://example.com' 
                  : '127.0.0.1'
              }
            />
            <TextField
              select
              label="Scan Type"
              value={scanType}
              onChange={handleScanTypeChange}
              fullWidth
              sx={{ mb: 2 }}
            >
              {scanTypes.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {type.icon} {type.label}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Output"
              value={output}
              onChange={e => setOutput(e.target.value)}
              sx={{ minWidth: 120 }}
            >
              {outputTypes.map(opt => (
                <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Scan Profile"
              value={scanProfile}
              onChange={e => setScanProfile(e.target.value)}
              sx={{ minWidth: 160 }}
            >
              {scanProfiles.map((opt: any) => (
                <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
              ))}
            </TextField>
          </Box>

          {/* Advanced Options */}
          <Box display="flex" alignItems="center" mb={2}>
            <Button
              variant="text"
              onClick={() => setShowAdvanced(!showAdvanced)}
              sx={{ mr: 2 }}
            >
              {showAdvanced ? "Hide" : "Show"} Advanced Options
            </Button>
          </Box>

          {showAdvanced && (
            <Box display="flex" gap={2} mb={2} flexWrap="wrap">
              <TextField
                type="number"
                label="Timeout (seconds)"
                value={timeout}
                onChange={e => setTimeout(Number(e.target.value))}
                sx={{ minWidth: 150 }}
                inputProps={{ min: 10, max: 300 }}
              />
              <Box display="flex" alignItems="center">
                <input
                  type="checkbox"
                  checked={useApi}
                  onChange={e => setUseApi(e.target.checked)}
                  id="use-api"
                />
                <label htmlFor="use-api" style={{ marginLeft: 8 }}>
                  Use NVD API for enhanced CVE detection
                </label>
              </Box>
            </Box>
          )}

          <Button
            variant="contained"
            color="primary"
            onClick={handleScan}
            disabled={
              loading ||
              !target ||
              ((scanType === "password" || scanType === "config") && systemInfo?.os !== "Linux")
            }
            size="large"
            sx={{ mt: 2, minWidth: 160 }}
          >
          {loading ? <CircularProgress size={24} /> : "Start Scan"}
          </Button>

          {(scanType === "password" || scanType === "config") && systemInfo?.os !== "Linux" && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            Password Audit and Config Audit are only supported on Linux systems. So scanning is disabled.
          </Alert>
          )}

          {/* System Info Display */}
          <SystemInfo systemInfo={systemInfo} />

          {/* HTML Report Info */}
          {report && isHtmlOutput && (
            <Alert severity="info" sx={{ mt: 2 }}>
              HTML report generated. Please download to view the full report.
            </Alert>
          )}

          {/* Port Scan Warning */}
          {report && !isHtmlOutput && (['ports', 'full'].includes(scanType)) && (() => {
            try {
              const data = JSON.parse(report);
              if (!data.ports || data.ports.length === 0) {
                return (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    No port scan results found in the report. This may indicate an error with the scan or nmap is not installed.
                  </Alert>
                );
              }
            } catch {}
            return null;
          })()}

          {/* Summary Cards */}
          {report && !isHtmlOutput && <ReportSummary summary={summary} />}

          {/* Charts */}
          {report && !isHtmlOutput && <ReportCharts cveSeverityData={cveSeverityData} portData={portData} />}

          {/* Detailed Results */}
          {report && <ReportDetails report={report} isHtmlOutput={isHtmlOutput} />}

          {/* Download Button */}
          {report && reportFilename && (
            <Box mt={2} display="flex" alignItems="center" gap={2}>
              <Button
                variant="outlined"
                color="secondary"
                startIcon={<DownloadIcon />}
                href={`${API_BASE_URL}/download?filename=${encodeURIComponent(reportFilename)}`}
                target="_blank"
                rel="noopener noreferrer"
                sx={{ mb: 2 }}
              >
                Download Report
              </Button>
            </Box>
          )}
          
          {/* Scan History */}
          <ScanHistory history={history} />

          <ScanAlerts error={error} report={report} isHtmlOutput={isHtmlOutput} scanType={scanType} systemInfo={systemInfo} />
        </Paper>
        <Box mt={6} textAlign="center" color="text.secondary">
          <Typography variant="body2">
            &copy; {new Date().getFullYear()} SecuScan &mdash; Security made simple and modular.
          </Typography>
        </Box>
      </Container>
    </>
  );
}

export default App;