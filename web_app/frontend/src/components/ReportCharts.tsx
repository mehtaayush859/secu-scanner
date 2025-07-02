import React from 'react';
import { Box, Typography } from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, Tooltip as ChartTooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts';

interface ReportChartsProps {
  cveSeverityData: Array<{ severity: string; count: number }>;
  portData: Array<{ state: string; count: number }>;
}

const ReportCharts: React.FC<ReportChartsProps> = ({ cveSeverityData, portData }) => (
  <Box mt={4} display="flex" flexDirection={{ xs: 'column', md: 'row' }} gap={2} alignItems="stretch">
    {cveSeverityData.length > 0 && (
      <Box flex={1}>
        <Typography variant="subtitle1" fontWeight="bold" mb={1}>
          CVEs by Severity
        </Typography>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={cveSeverityData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="severity" />
            <YAxis allowDecimals={false} />
            <ChartTooltip />
            <Legend />
            <Bar dataKey="count" fill="#d32f2f" />
          </BarChart>
        </ResponsiveContainer>
      </Box>
    )}
    {portData.length > 0 && (
      <Box flex={1}>
        <Typography variant="subtitle1" fontWeight="bold" mb={1}>
          Ports by State
        </Typography>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={portData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="state" />
            <YAxis allowDecimals={false} />
            <ChartTooltip />
            <Legend />
            <Bar dataKey="count" fill="#1976d2" />
          </BarChart>
        </ResponsiveContainer>
      </Box>
    )}
  </Box>
);

export default ReportCharts; 