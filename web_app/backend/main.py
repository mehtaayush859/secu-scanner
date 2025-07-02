from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import subprocess
import os
import datetime
import platform
import time
import json
from enum import Enum

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# CORS origins based on environment
if ENVIRONMENT == "production":
    CORS_ORIGINS = [
        "https://secuscan.vercel.app",  # Your Vercel frontend
        "https://secuscan-git-main-mehtaayush859.vercel.app",  # Vercel preview
    ]
else:
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

app = FastAPI(
    title="SecuScan Web API",
    description="Advanced Vulnerability & Misconfiguration Scanner Web API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enhanced request models
class ScanProfile(str, Enum):
    default = "default"
    stealth = "stealth"
    aggressive = "aggressive"
    vuln = "vuln"

class ScanType(str, Enum):
    full = "full"
    ports = "ports"
    cve = "cve"
    web = "web"
    password = "password"
    config = "config"
    network = "network"

class OutputFormat(str, Enum):
    json = "json"
    html = "html"

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address, hostname, URL, or network range")
    scan_type: ScanType = Field(default=ScanType.full, description="Type of scan to perform")
    output: OutputFormat = Field(default=OutputFormat.json, description="Report output format")
    scan_profile: ScanProfile = Field(default=ScanProfile.default, description="Scan profile for port scanning")
    use_api: bool = Field(default=False, description="Use NVD API for enhanced CVE detection")
    timeout: int = Field(default=30, description="Timeout for web scans in seconds")
    report_name: Optional[str] = Field(None, description="Custom report filename")

class QuickScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or URL")
    output: OutputFormat = Field(default=OutputFormat.json, description="Report output format")

class ComprehensiveScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or URL")
    output: OutputFormat = Field(default=OutputFormat.html, description="Report output format")

class ScanStatus(BaseModel):
    scan_id: str
    status: str  # "running", "completed", "failed"
    progress: int = 0
    message: str = ""
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

# Global scan status tracking
scan_status = {}

def get_reports_dir():
    # Get the backend directory
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up two levels to reach the project root
    project_root = os.path.dirname(os.path.dirname(backend_dir))
    # Return the reports/html path
    reports_dir = os.path.join(project_root, "reports", "html")
    return os.environ.get("SECUAUTH_REPORTS_DIR", reports_dir)

def get_cli_path():
    # Get the backend directory
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up two levels to reach the project root
    project_root = os.path.dirname(os.path.dirname(backend_dir))
    # Return the main.py path
    cli_path = os.path.join(project_root, "main.py")
    return cli_path

@app.get("/")
async def root():
    """API root endpoint with version info."""
    return {
        "name": "SecuScan Web API",
        "version": "2.0.0",
        "description": "Advanced Vulnerability & Misconfiguration Scanner",
        "endpoints": {
            "scan": "/scan",
            "quick_scan": "/quick-scan",
            "comprehensive_scan": "/comprehensive-scan",
            "scan_status": "/scan-status/{scan_id}",
            "download": "/download",
            "history": "/history",
            "system_info": "/system_info",
            "capabilities": "/capabilities"
        }
    }

@app.post("/scan", response_model=Dict[str, Any])
async def scan(req: ScanRequest):
    """Run a custom scan with all available options."""
    try:
        # Validate scan parameters
        validation_result = validate_scan_request(req)
        if not validation_result["valid"]:
            raise HTTPException(status_code=400, detail=validation_result["errors"])
        
        # Check if CLI tool exists
        cli_path = get_cli_path()
        if not os.path.exists(cli_path):
            raise HTTPException(status_code=500, detail=f"CLI tool not found at: {cli_path}")
        
        # Ensure reports directory exists
        reports_dir = get_reports_dir()
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate unique scan ID
        scan_id = f"scan_{int(time.time())}_{hash(req.target) % 10000}"
        
        # Generate report filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = req.report_name or f"scan_report_{timestamp}.{req.output}"
        
        # Build command
        cmd = [
            "python", cli_path,
            "--target", req.target,
            "--scan-type", req.scan_type,
            "--output", req.output,
            "--scan-profile", req.scan_profile,
            "--report-name", report_filename
        ]
        
        if req.use_api:
            cmd.append("--use-api")
        
        if req.timeout != 30:
            cmd.extend(["--timeout", str(req.timeout)])
        
        print(f"Running command: {' '.join(cmd)}")  # Debug log
        print(f"Working directory: {os.path.dirname(cli_path)}")  # Debug log
        print(f"Reports directory: {reports_dir}")  # Debug log
        
        # Set environment variables for proper module imports
        env = os.environ.copy()
        env['PYTHONPATH'] = os.path.dirname(cli_path) + os.pathsep + env.get('PYTHONPATH', '')
        
        # Run scan
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(cli_path), env=env)
        
        # Check if command failed
        if result.returncode != 0:
            error_msg = f"CLI tool failed with return code {result.returncode}"
            if result.stderr:
                error_msg += f"\nSTDERR: {result.stderr}"
            if result.stdout:
                error_msg += f"\nSTDOUT: {result.stdout}"
            print(f"CLI Error: {error_msg}")  # Debug log
            raise HTTPException(status_code=500, detail=error_msg)
        else:
            print(f"CLI stdout: {result.stdout}")  # Debug log
            print(f"CLI stderr: {result.stderr}")  # Debug log
        
        # Check for report file
        report_path = os.path.join(reports_dir, report_filename)
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "report": content,
                    "filename": report_filename,
                    "scan_type": req.scan_type,
                    "target": req.target,
                    "timestamp": datetime.datetime.now().isoformat()
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to read report file: {str(e)}")
        else:
            # Try to find any generated report file
            files = [f for f in os.listdir(reports_dir) if f.endswith(f".{req.output}")]
            if files:
                latest_file = max(files, key=lambda x: os.path.getmtime(os.path.join(reports_dir, x)))
                report_path = os.path.join(reports_dir, latest_file)
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "report": content,
                    "filename": latest_file,
                    "scan_type": req.scan_type,
                    "target": req.target,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "note": f"Used generated file: {latest_file}"
                }
            else:
                raise HTTPException(status_code=500, detail=f"Report file not generated. CLI output: {result.stdout}")
            
    except subprocess.CalledProcessError as e:
        error_msg = f"Scan failed: {e.stderr or str(e)}"
        if e.stdout:
            error_msg += f"\nSTDOUT: {e.stdout}"
        raise HTTPException(status_code=500, detail=error_msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.post("/quick-scan", response_model=Dict[str, Any])
async def quick_scan(req: QuickScanRequest):
    """Run a quick security assessment."""
    try:
        cmd = [
            "python", get_cli_path(),
            "--target", req.target,
            "--quick",
            "--output", req.output
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Find the generated report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"quick_scan_{timestamp}.{req.output}"
        report_path = os.path.join(get_reports_dir(), report_filename)
        
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            return {
                "success": True,
                "scan_type": "quick",
                "report": content,
                "filename": report_filename,
                "target": req.target,
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Quick scan report not generated")
            
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {e.stderr or str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/comprehensive-scan", response_model=Dict[str, Any])
async def comprehensive_scan(req: ComprehensiveScanRequest):
    """Run a comprehensive security assessment."""
    try:
        cmd = [
            "python", get_cli_path(),
            "--target", req.target,
            "--comprehensive",
            "--output", req.output
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Find the generated report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"comprehensive_scan_{timestamp}.{req.output}"
        report_path = os.path.join(get_reports_dir(), report_filename)
        
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            return {
                "success": True,
                "scan_type": "comprehensive",
                "report": content,
                "filename": report_filename,
                "target": req.target,
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Comprehensive scan report not generated")
            
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Comprehensive scan failed: {e.stderr or str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan-status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the status of a running scan."""
    if scan_id in scan_status:
        return scan_status[scan_id]
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/download")
async def download_report(filename: str):
    """Download a scan report file."""
    report_dir = get_reports_dir()
    report_path = os.path.join(report_dir, filename)
    
    if os.path.exists(report_path):
        return FileResponse(
            report_path, 
            filename=os.path.basename(report_path), 
            media_type="application/octet-stream"
        )
    else:
        raise HTTPException(status_code=404, detail="Report not found")

@app.get("/history")
async def list_history(format: str = "json", limit: int = 20):
    """List recent scan reports."""
    report_dir = get_reports_dir()
    ext = format if format in ("json", "html") else "json"
    
    try:
        files = [
            f for f in os.listdir(report_dir)
            if f.startswith(("scan_report_", "quick_scan_", "comprehensive_scan_")) and f.endswith(f".{ext}")
        ]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(report_dir, x)), reverse=True)
        
        # Get file metadata
        file_info = []
        for file in files[:limit]:
            file_path = os.path.join(report_dir, file)
            stat = os.stat(file_path)
            file_info.append({
                "filename": file,
                "size": stat.st_size,
                "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "scan_type": extract_scan_type_from_filename(file)
            })
        
        return {"history": file_info}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system_info")
async def system_info():
    """Get system information and capabilities."""
    try:
        # Check if CLI tools are available
        cli_path = get_cli_path()
        cli_available = os.path.exists(cli_path)
        
        # Check for nmap
        nmap_available = False
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            nmap_available = True
        except:
            pass
        
        # Check for NVD API key
        nvd_api_key = os.environ.get("NVD_API_KEY", "")
        
        return {
            "os": platform.system(),
            "os_version": platform.release(),
            "python_version": platform.python_version(),
            "cli_available": cli_available,
            "nmap_available": nmap_available,
            "nvd_api_configured": bool(nvd_api_key),
            "reports_directory": get_reports_dir()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/capabilities")
async def get_capabilities():
    """Get available scan capabilities and options."""
    return {
        "scan_types": {
            "full": "Complete security assessment",
            "ports": "Port scanning and service detection",
            "cve": "CVE vulnerability detection",
            "web": "Web application security analysis",
            "password": "Password security audit (Linux only)",
            "config": "Configuration security audit (Linux only)",
            "network": "Network discovery and security analysis"
        },
        "scan_profiles": {
            "default": "Standard scan (top 1000 ports, T4)",
            "stealth": "Stealth scan (top 100 ports, T2)",
            "aggressive": "Aggressive scan (all ports, T5)",
            "vuln": "Vulnerability scan (with nmap scripts)"
        },
        "output_formats": ["json", "html"],
        "features": {
            "nvd_api_integration": "Real-time CVE lookups",
            "ssl_tls_analysis": "Certificate and cipher analysis",
            "network_discovery": "Host and service enumeration",
            "risk_assessment": "Automated risk scoring",
            "security_grading": "A-F security grades"
        }
    }

@app.get("/test-cli")
async def test_cli():
    """Test if the CLI tool is working properly."""
    try:
        cli_path = get_cli_path()
        if not os.path.exists(cli_path):
            return {
                "success": False,
                "error": f"CLI tool not found at: {cli_path}",
                "cli_path": cli_path
            }
        
        # Test basic CLI functionality
        cmd = ["python", cli_path, "--help"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(cli_path))
        
        if result.returncode == 0:
            return {
                "success": True,
                "message": "CLI tool is working",
                "cli_path": cli_path,
                "help_output": result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout
            }
        else:
            return {
                "success": False,
                "error": f"CLI tool failed with return code {result.returncode}",
                "stderr": result.stderr,
                "stdout": result.stdout
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Test failed: {str(e)}",
            "cli_path": get_cli_path()
        }

def validate_scan_request(req: ScanRequest) -> Dict[str, Any]:
    """Validate scan request parameters."""
    result = {"valid": True, "errors": []}
    
    # Validate target
    if not req.target:
        result["errors"].append("Target is required")
        result["valid"] = False
    
    # Validate network scan target
    if req.scan_type == ScanType.network:
        try:
            import ipaddress
            ipaddress.IPv4Network(req.target, strict=False)
        except ValueError:
            result["errors"].append("Network scan target should be a valid network range (e.g., 192.168.1.0/24)")
            result["valid"] = False
    
    # Validate web scan target
    if req.scan_type == ScanType.web and not (req.target.startswith(('http://', 'https://')) or '://' in req.target):
        result["errors"].append("Web scan target should be a URL (http:// or https://)")
        result["valid"] = False
    
    # Platform-specific warnings
    if req.scan_type in [ScanType.password, ScanType.config] and platform.system() != "Linux":
        result["errors"].append(f"{req.scan_type} scan is only supported on Linux")
        result["valid"] = False
    
    return result

def extract_scan_type_from_filename(filename: str) -> str:
    """Extract scan type from filename."""
    if filename.startswith("quick_scan_"):
        return "quick"
    elif filename.startswith("comprehensive_scan_"):
        return "comprehensive"
    elif filename.startswith("scan_report_"):
        return "custom"
    else:
        return "unknown"

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom exception handler for better error responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "timestamp": datetime.datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "details": str(exc),
            "timestamp": datetime.datetime.now().isoformat()
        }
    )