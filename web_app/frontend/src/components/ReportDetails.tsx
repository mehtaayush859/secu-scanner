import React from 'react';
import { Box, Typography, Paper } from '@mui/material';

interface ReportDetailsProps {
  report: string;
  isHtmlOutput: boolean;
}

const ReportDetails: React.FC<ReportDetailsProps> = ({ report, isHtmlOutput }) => {
  if (isHtmlOutput) return null;
  try {
    const data = JSON.parse(report);
    // Fallback for port scan key
    const portsArr = data.ports || data.port_results || [];
    return (
      <Box>
        {/* Ports */}
        {Array.isArray(portsArr) && portsArr.length > 0 && (
          <Box mt={3}>
            <Typography variant="subtitle1" fontWeight="bold" color="primary">
              Open Ports
            </Typography>
            <Paper sx={{ p: 2, mt: 1, mb: 2, background: '#f8fafd' }}>
              <table style={{ width: '100%', fontSize: 14 }}>
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                  </tr>
                </thead>
                <tbody>
                  {portsArr.map((p: any, idx: number) => (
                    <tr key={idx}>
                      <td>{p.port}</td>
                      <td>{p.state}</td>
                      <td>{p.service}</td>
                      <td>{p.version}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Paper>
          </Box>
        )}
        {/* CVEs */}
        {data.cves && data.cves[0]?.cve_findings && (
          <Box mt={3}>
            <Typography variant="subtitle1" fontWeight="bold" color="error">
              CVE Vulnerabilities
            </Typography>
            <Paper sx={{ p: 2, mt: 1, mb: 2, background: '#fff8f8' }}>
              {data.cves[0].cve_findings.length === 0 ||
                (data.cves[0].cve_findings.length === 1 && data.cves[0].cve_findings[0].info) ? (
                <Typography color="success.main">No known CVEs detected for installed software.</Typography>
              ) : (
                <table style={{ width: '100%', fontSize: 14 }}>
                  <thead>
                    <tr>
                      <th>CVE ID</th>
                      <th>Software</th>
                      <th>Version</th>
                      <th>Severity</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.cves[0].cve_findings.map((cve: any, idx: number) =>
                      cve.cve_id ? (
                        <tr key={idx}>
                          <td>
                            <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer">
                              {cve.cve_id}
                            </a>
                          </td>
                          <td>{cve.software}</td>
                          <td>{cve.version}</td>
                          <td>{cve.severity}</td>
                          <td>{cve.description}</td>
                        </tr>
                      ) : null
                    )}
                  </tbody>
                </table>
              )}
            </Paper>
            {/* Show checked software */}
            {data.cves[0].software_checked && (
              <Box mt={2}>
                <Typography variant="body2" color="text.secondary" fontWeight="bold">
                  Software Checked:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
                  {data.cves[0].software_checked.map((sw: any, idx: number) => (
                    <Paper key={idx} sx={{ px: 1.5, py: 0.5, fontSize: 13, background: '#f4f4f4' }}>
                      {sw.name} ({sw.version})
                    </Paper>
                  ))}
                </Box>
              </Box>
            )}
          </Box>
        )}
        {/* Web Headers */}
        {data.web && (
          <Box mt={3}>
            <Typography variant="subtitle1" fontWeight="bold" color="secondary">
              Web Header Security
            </Typography>
            <Paper sx={{ p: 2, mt: 1, mb: 2, background: '#f8fff8' }}>
              {data.web.error ? (
                <Typography color="error">{data.web.error}</Typography>
              ) : (
                <>
                  <Typography variant="body2" fontWeight="bold">Missing Headers:</Typography>
                  <ul>
                    {data.web.missing && data.web.missing.length > 0 ? (
                      data.web.missing.map((h: string, idx: number) => (
                        <li key={idx}>{h}</li>
                      ))
                    ) : (
                      <li>None</li>
                    )}
                  </ul>
                  <Typography variant="body2" fontWeight="bold" mt={2}>All Headers:</Typography>
                  <ul>
                    {data.web.headers && Object.entries(data.web.headers).map(([k, v], idx) => (
                      <li key={idx}><b>{k}:</b> {v as string}</li>
                    ))}
                  </ul>
                </>
              )}
            </Paper>
          </Box>
        )}
        {/* Password Audit */}
        {data.password && Array.isArray(data.password) && (
          <Box mt={3}>
            <Typography variant="subtitle1" fontWeight="bold" color="warning.main">
              Password Audit
            </Typography>
            <Paper sx={{ p: 2, mt: 1, mb: 2, background: '#fffbe6' }}>
              {data.password[0]?.error ? (
                <Typography color="error">{data.password[0].error}</Typography>
              ) : (
                <table style={{ width: '100%', fontSize: 14 }}>
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Status</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.password.map((p: any, idx: number) => (
                      <tr key={idx}>
                        <td>{p.user}</td>
                        <td>{p.status}</td>
                        <td>{p.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Paper>
          </Box>
        )}
        {/* Config Audit */}
        {data.config && data.config.ssh_config && (
          <Box mt={3}>
            <Typography variant="subtitle1" fontWeight="bold" color="info.main">
              SSH Config Audit
            </Typography>
            <Paper sx={{ p: 2, mt: 1, mb: 2, background: '#e8f4fa' }}>
              <table style={{ width: '100%', fontSize: 14 }}>
                <thead>
                  <tr>
                    <th>Setting</th>
                    <th>Status</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {data.config.ssh_config.map((c: any, idx: number) => (
                    <tr key={idx}>
                      <td>{c.setting}</td>
                      <td>{c.status}</td>
                      <td>{c.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Paper>
          </Box>
        )}
      </Box>
    );
  } catch {
    return null;
  }
};

export default ReportDetails; 