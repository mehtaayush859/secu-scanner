import React from 'react';
import { Alert, Typography } from '@mui/material';

interface ScanAlertsProps {
  error?: string;
  report?: string;
  isHtmlOutput?: boolean;
  scanType?: string;
  systemInfo?: any;
  errors?: string[];
  loading?: boolean;
}

const ScanAlerts: React.FC<ScanAlertsProps> = ({ error, report, isHtmlOutput, scanType, systemInfo, errors }) => (
  <>
    {/* Error Alert */}
    {error && (
      <Alert severity="error" sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Error:
        </Typography>
        {error}
      </Alert>
    )}
    {/* Form Validation Errors (for ScanForm) */}
    {errors && errors.length > 0 && (
      <Alert severity="error" sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Configuration Errors:
        </Typography>
        <ul style={{ margin: 0, paddingLeft: 20 }}>
          {errors.map((err, idx) => <li key={idx}>{err}</li>)}
        </ul>
      </Alert>
    )}
    {/* Info Alert for HTML report */}
    {report && isHtmlOutput && (
      <Alert severity="info" sx={{ mt: 2 }}>
        HTML report generated. Please download to view the full report.
      </Alert>
    )}
    {/* Port Scan Warning */}
    {report && !isHtmlOutput && (scanType === 'ports' || scanType === 'full') && (() => {
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
    {/* Password/Config Scan Warning for non-Linux */}
    {(scanType === 'password' || scanType === 'config') && systemInfo?.os !== 'Linux' && (
      <Alert severity="warning" sx={{ mt: 2 }}>
        Password Audit and Config Audit are only supported on Linux systems. So scanning is disabled.
      </Alert>
    )}
  </>
);

export default ScanAlerts; 