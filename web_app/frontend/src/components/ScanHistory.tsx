import React from 'react';
import { Box, Typography, Divider } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import HistoryIcon from '@mui/icons-material/History';

interface ScanHistoryProps {
  history: Array<{
    filename: string;
    scan_type: string;
    size: number;
    modified: string;
  }>;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ history }) => (
  history.length > 0 ? (
    <Box mt={4}>
      <Divider sx={{ mb: 2 }} />
      <Typography variant="h6" color="primary">
        <HistoryIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Scan History
      </Typography>
      <Box>
        {history.map((file) => (
          <Box key={file.filename} mb={1} p={1} border={1} borderColor="grey.200" borderRadius={1}>
            <Box display="flex" alignItems="center" justifyContent="space-between">
              <Box display="flex" alignItems="center">
                <DownloadIcon sx={{ mr: 1, color: '#1976d2' }} />
                <a
                  href={`http://localhost:8000/download?filename=${encodeURIComponent(file.filename)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ textDecoration: 'none', color: '#1976d2', fontWeight: 'bold' }}
                >
                  {file.filename}
                </a>
              </Box>
              <Box display="flex" gap={2} alignItems="center">
                <Typography variant="caption" color="text.secondary">
                  {file.scan_type}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {(file.size / 1024).toFixed(1)} KB
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {new Date(file.modified).toLocaleDateString()}
                </Typography>
              </Box>
            </Box>
          </Box>
        ))}
      </Box>
    </Box>
  ) : null
);

export default ScanHistory; 