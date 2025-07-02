import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Switch,
  FormControlLabel,
  Chip,
  Alert,
  Divider,
  Tooltip,
  IconButton,
  Collapse,
  CircularProgress
} from '@mui/material';
import { styled } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import WifiIcon from '@mui/icons-material/Wifi';
import BugReportIcon from '@mui/icons-material/BugReport';
import WebIcon from '@mui/icons-material/Web';
import DownloadIcon from '@mui/icons-material/Download';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ApiIcon from '@mui/icons-material/Api';
import ScanAlerts from './ScanAlerts';

// Styled components
const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
  color: 'white',
  marginBottom: theme.spacing(3),
  '& .MuiCardContent-root': {
    padding: theme.spacing(3)
  }
}));

const ScanTypeCard = styled(Card)<{ selected: boolean }>(({ theme, selected }) => ({
  cursor: 'pointer',
  transition: 'all 0.3s ease',
  border: selected ? `2px solid ${theme.palette.primary.main}` : '2px solid transparent',
  background: selected ? theme.palette.primary.light + '20' : 'white',
  '&:hover': {
    transform: 'translateY(-2px)',
    boxShadow: theme.shadows[8]
  }
}));

// Scan type configurations
const scanTypes = [
  { value: 'full', label: 'Full Scan', description: 'Complete security assessment', icon: <SecurityIcon /> },
  { value: 'ports', label: 'Port Scan', description: 'Network port analysis', icon: <WifiIcon /> },
  { value: 'cve', label: 'CVE Check', description: 'Vulnerability database lookup', icon: <BugReportIcon /> },
  { value: 'web', label: 'Web Scan', description: 'Web application security', icon: <WebIcon /> },
  { value: 'password', label: 'Password Audit', description: 'Password policy analysis', icon: <SecurityIcon /> },
  { value: 'config', label: 'Config Audit', description: 'Configuration file analysis', icon: <SecurityIcon /> },
  { value: 'network', label: 'Network Discovery', description: 'Network topology mapping', icon: <WifiIcon /> }
];

const scanProfiles = [
  { value: 'default', label: 'Default', description: 'Standard security scan' },
  { value: 'aggressive', label: 'Aggressive', description: 'Fast but noisy scan' },
  { value: 'stealth', label: 'Stealth', description: 'Slow but quiet scan' },
  { value: 'vuln', label: 'Vulnerability', description: 'Nmap vuln script scan' }
];

interface ScanFormProps {
  onSubmit: (scanData: any) => void;
  loading: boolean;
  systemInfo: any;
}

const ScanForm: React.FC<ScanFormProps> = ({ onSubmit, loading, systemInfo }) => {
  const [scanMode, setScanMode] = useState<'custom' | 'quick' | 'comprehensive'>('custom');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [scanProfile, setScanProfile] = useState('default');
  const [output, setOutput] = useState('json');
  const [useApi, setUseApi] = useState(false);
  const [timeout, setTimeout] = useState(30);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  // Validate form
  const validateForm = () => {
    const newErrors: string[] = [];
    
    if (!target.trim()) {
      newErrors.push('Target is required');
    }
    
    if (scanType === 'network') {
      try {
        // Basic network range validation
        if (!target.includes('/')) {
          newErrors.push('Network scan requires CIDR notation (e.g., 192.168.1.0/24)');
        }
      } catch {
        newErrors.push('Invalid network range format');
      }
    }
    
    if (scanType === 'web' && !target.startsWith('http')) {
      newErrors.push('Web scan target should be a URL (http:// or https://)');
    }
    
    if (['password', 'config'].includes(scanType) && systemInfo?.os !== 'Linux') {
      newErrors.push(`${scanType} scan is only supported on Linux systems`);
    }
    
    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    let scanData: any = { target };
    
    if (scanMode === 'quick') {
      scanData = { target, output };
    } else if (scanMode === 'comprehensive') {
      scanData = { target, output };
    } else {
      scanData = {
        target,
        scan_type: scanType,
        scan_profile: scanProfile,
        output,
        use_api: useApi,
        timeout
      };
    }
    
    onSubmit(scanData);
  };

  const handleQuickScan = () => {
    setScanMode('quick');
    setShowAdvanced(false);
  };

  const handleComprehensiveScan = () => {
    setScanMode('comprehensive');
    setShowAdvanced(false);
  };

  const handleCustomScan = () => {
    setScanMode('custom');
  };

  return (
    <Box component="form" onSubmit={handleSubmit}>
      {/* Scan Mode Selection */}
      <StyledCard>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Choose Scan Mode
          </Typography>
          <Box display="flex" flexWrap="wrap" gap={2} sx={{ mt: 2 }}>
            <Box flex="1" minWidth={300}>
              <ScanTypeCard 
                selected={scanMode === 'quick'}
                onClick={handleQuickScan}
              >
                <CardContent>
                  <Typography variant="h6" color="primary">
                    🚀 Quick Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Fast security assessment with essential checks
                  </Typography>
                </CardContent>
              </ScanTypeCard>
            </Box>
            <Box flex="1" minWidth={300}>
              <ScanTypeCard 
                selected={scanMode === 'comprehensive'}
                onClick={handleComprehensiveScan}
              >
                <CardContent>
                  <Typography variant="h6" color="primary">
                    🔍 Comprehensive Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Complete security assessment with all features
                  </Typography>
                </CardContent>
              </ScanTypeCard>
            </Box>
            <Box flex="1" minWidth={300}>
              <ScanTypeCard 
                selected={scanMode === 'custom'}
                onClick={handleCustomScan}
              >
                <CardContent>
                  <Typography variant="h6" color="primary">
                    ⚙️ Custom Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Configure specific scan parameters
                  </Typography>
                </CardContent>
              </ScanTypeCard>
            </Box>
          </Box>
        </CardContent>
      </StyledCard>

      {/* Target Input */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Target Configuration
          </Typography>
          <TextField
            fullWidth
            label="Target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              scanType === 'network' 
                ? '192.168.1.0/24' 
                : scanType === 'web' 
                ? 'https://example.com' 
                : '127.0.0.1'
            }
            helperText={
              scanType === 'network' 
                ? 'Enter network range (CIDR notation)' 
                : scanType === 'web' 
                ? 'Enter URL with protocol' 
                : 'Enter IP address or hostname'
            }
            sx={{ mb: 2 }}
          />
        </CardContent>
      </Card>

      {/* Custom Scan Configuration */}
      {scanMode === 'custom' && (
        <>
          {/* Scan Type Selection */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Type
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={2}>
                {scanTypes.map((type) => (
                  <Box flex="1" minWidth={250} key={type.value}>
                    <ScanTypeCard 
                      selected={scanType === type.value}
                      onClick={() => setScanType(type.value)}
                    >
                      <CardContent>
                        <Box display="flex" alignItems="center" mb={1}>
                          {type.icon}
                          <Typography variant="subtitle1" sx={{ ml: 1 }}>
                            {type.label}
                          </Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          {type.description}
                        </Typography>
                      </CardContent>
                    </ScanTypeCard>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>

          {/* Advanced Options */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Typography variant="h6">
                  Advanced Options
                </Typography>
                <IconButton onClick={() => setShowAdvanced(!showAdvanced)}>
                  {showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                </IconButton>
              </Box>
              
              <Collapse in={showAdvanced}>
                <Box display="flex" flexWrap="wrap" gap={2} sx={{ mt: 2 }}>
                  <Box flex="1" minWidth={250}>
                    <FormControl fullWidth>
                      <InputLabel>Scan Profile</InputLabel>
                      <Select
                        value={scanProfile}
                        onChange={(e) => setScanProfile(e.target.value)}
                        label="Scan Profile"
                      >
                        {scanProfiles.map((profile) => (
                          <MenuItem key={profile.value} value={profile.value}>
                            <Box>
                              <Typography variant="body1">{profile.label}</Typography>
                              <Typography variant="caption" color="text.secondary">
                                {profile.description}
                              </Typography>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Box>
                  
                  <Box flex="1" minWidth={250}>
                    <FormControl fullWidth>
                      <InputLabel>Output Format</InputLabel>
                      <Select
                        value={output}
                        onChange={(e) => setOutput(e.target.value)}
                        label="Output Format"
                      >
                        <MenuItem value="json">JSON</MenuItem>
                        <MenuItem value="html">HTML</MenuItem>
                      </Select>
                    </FormControl>
                  </Box>
                  
                  <Box flex="1" minWidth={250}>
                    <TextField
                      fullWidth
                      type="number"
                      label="Timeout (seconds)"
                      value={timeout}
                      onChange={(e) => setTimeout(Number(e.target.value))}
                      inputProps={{ min: 10, max: 300 }}
                    />
                  </Box>
                  
                  <Box flex="1" minWidth={250}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={useApi}
                          onChange={(e) => setUseApi(e.target.checked)}
                        />
                      }
                      label={
                        <Box display="flex" alignItems="center">
                          <ApiIcon sx={{ mr: 1 }} />
                          Use NVD API
                        </Box>
                      }
                    />
                  </Box>
                </Box>
              </Collapse>
            </CardContent>
          </Card>
        </>
      )}

      {/* System Compatibility Warnings */}
      {systemInfo && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              System Information
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={2}>
              <Box flex="1" minWidth={200}>
                <Chip 
                  label={`OS: ${systemInfo.os}`} 
                  color={systemInfo.os === 'Linux' ? 'success' : 'warning'}
                  variant="outlined"
                />
              </Box>
              <Box flex="1" minWidth={200}>
                <Chip 
                  label={`Nmap: ${systemInfo.nmap_available ? 'Available' : 'Not Found'}`}
                  color={systemInfo.nmap_available ? 'success' : 'error'}
                  variant="outlined"
                />
              </Box>
              <Box flex="1" minWidth={200}>
                <Chip 
                  label={`NVD API: ${systemInfo.nvd_api_configured ? 'Configured' : 'Not Configured'}`}
                  color={systemInfo.nvd_api_configured ? 'success' : 'warning'}
                  variant="outlined"
                />
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      <ScanAlerts errors={errors} loading={loading} />

      {/* Submit Button */}
      <Box display="flex" justifyContent="center">
        <Button
          type="submit"
          variant="contained"
          size="large"
          disabled={loading || errors.length > 0}
          startIcon={<SecurityIcon />}
          sx={{
            minWidth: 200,
            height: 56,
            fontSize: '1.1rem',
            background: 'linear-gradient(45deg, #FE6B8B 30%, #FF8E53 90%)',
            '&:hover': {
              background: 'linear-gradient(45deg, #FE6B8B 60%, #FF8E53 90%)',
            }
          }}
        >
          {loading ? <CircularProgress size={24} /> : 'Start Scan'}
        </Button>
      </Box>
    </Box>
  );
};

export default ScanForm; 