import React from 'react';
import { Card, CardContent, Typography, Stack } from '@mui/material';

interface ReportSummaryProps {
  summary: {
    ports: number;
    cves: number;
    web: number;
  };
}

const ReportSummary: React.FC<ReportSummaryProps> = ({ summary }) => (
  <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} mt={4}>
    <Card sx={{ flex: 1 }}>
      <CardContent>
        <Typography variant="h6">Open Ports</Typography>
        <Typography variant="h4">{summary.ports}</Typography>
      </CardContent>
    </Card>
    <Card sx={{ flex: 1 }}>
      <CardContent>
        <Typography variant="h6">CVEs Found</Typography>
        <Typography variant="h4">{summary.cves}</Typography>
      </CardContent>
    </Card>
    <Card sx={{ flex: 1 }}>
      <CardContent>
        <Typography variant="h6">Missing Headers</Typography>
        <Typography variant="h4">{summary.web}</Typography>
      </CardContent>
    </Card>
  </Stack>
);

export default ReportSummary; 