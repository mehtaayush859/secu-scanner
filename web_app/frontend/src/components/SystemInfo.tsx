import React from 'react';
import { Box, Typography, Chip } from '@mui/material';

interface SystemInfoProps {
  systemInfo: {
    os?: string;
    nmap_available?: boolean;
    nvd_api_configured?: boolean;
  };
}

const SystemInfo: React.FC<SystemInfoProps> = ({ systemInfo }) => (
  systemInfo && Object.keys(systemInfo).length > 0 ? (
    <Box mt={2} p={2} border={1} borderColor="grey.300" borderRadius={1}>
      <Typography variant="subtitle2" fontWeight="bold" mb={1}>
        System Information:
      </Typography>
      <Box display="flex" gap={2} flexWrap="wrap">
        <Typography variant="body2">
          OS: {systemInfo.os || 'Unknown'}
        </Typography>
        <Typography variant="body2">
          Nmap: {systemInfo.nmap_available ? 'Available' : 'Not Found'}
        </Typography>
        <Typography variant="body2">
          NVD API: {systemInfo.nvd_api_configured ? 'Configured' : 'Not Configured'}
        </Typography>
      </Box>
    </Box>
  ) : null
);

export default SystemInfo; 