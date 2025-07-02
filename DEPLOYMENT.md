# 🚀 SecuScan Deployment Guide

## 📋 Pre-Deployment Checklist

### ✅ Prerequisites
- [ ] Git repository is clean and up-to-date
- [ ] All tests are passing (`python -m pytest tests/`)
- [ ] CLI tools are working (`python main.py --help`)
- [ ] Frontend builds successfully (`npm run build`)
- [ ] Backend starts without errors (`python -m uvicorn web_app.backend.main:app`)

### 🔧 Configuration Updates
- [ ] Update `config.yaml` with production settings
- [ ] Set environment variables in deployment platform
- [ ] Update CORS origins in backend
- [ ] Configure API URLs in frontend

---

## 🌐 Deployment Options

### Option 1: Vercel (Recommended)

**Pros:**
- ✅ Free tier with generous limits
- ✅ Excellent for React frontend
- ✅ Fast global CDN
- ✅ Easy GitHub integration
- ✅ Automatic deployments

**Steps:**

1. **Install Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Login to Vercel:**
   ```bash
   vercel login
   ```

3. **Configure Environment Variables:**
   - Go to Vercel Dashboard → Your Project → Settings → Environment Variables
   - Add:
     ```
     ENVIRONMENT=production
     API_HOST=0.0.0.0
     API_PORT=8000
     REACT_APP_API_URL=https://your-backend-url.vercel.app
     ```

4. **Deploy:**
   ```bash
   ./deploy-vercel.sh
   ```

5. **Update CORS Origins:**
   - Edit `web_app/backend/main.py`
   - Replace `your-app.vercel.app` with your actual domain

### Option 2: Railway

**Pros:**
- ✅ Full-stack deployment
- ✅ Docker support
- ✅ Easy environment management
- ✅ Good free tier

**Steps:**

1. **Install Railway CLI:**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway:**
   ```bash
   railway login
   ```

3. **Deploy:**
   ```bash
   ./deploy-railway.sh
   ```

4. **Configure Environment Variables:**
   - Go to Railway Dashboard → Your Project → Variables
   - Add the same variables as Vercel

### Option 3: Render

**Pros:**
- ✅ Good for backend-heavy apps
- ✅ Free tier available
- ✅ Easy setup

**Steps:**

1. **Connect GitHub repository**
2. **Create new Web Service**
3. **Configure:**
   - Build Command: `pip install -r requirements.txt && pip install -r web_app/backend/requirements.txt`
   - Start Command: `python -m uvicorn web_app.backend.main:app --host 0.0.0.0 --port $PORT`

---

## 🔒 Security Configuration

### Environment Variables
```bash
# Required
ENVIRONMENT=production
SECRET_KEY=your-secure-secret-key
API_HOST=0.0.0.0
API_PORT=8000

# Optional
NVD_API_KEY=your-nvd-api-key
SENTRY_DSN=your-sentry-dsn
```

### CORS Configuration
Update `web_app/backend/main.py`:
```python
CORS_ORIGINS = [
    "https://your-actual-domain.com",
    "https://www.your-actual-domain.com",
]
```

### Security Headers
Add to your deployment platform:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## 📊 Monitoring & Analytics

### Health Checks
- Endpoint: `/`
- Expected: 200 OK with API info

### Logging
- Application logs: Check deployment platform dashboard
- Error tracking: Set up Sentry (optional)

### Performance
- Monitor API response times
- Check memory usage
- Track scan completion rates

---

## 🔄 CI/CD Setup

### GitHub Actions (Optional)
Create `.github/workflows/deploy.yml`:
```yaml
name: Deploy to Vercel
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install -g vercel
      - run: vercel --prod --token ${{ secrets.VERCEL_TOKEN }}
```

---

## 🚨 Troubleshooting

### Common Issues

1. **CORS Errors:**
   - Check CORS origins in backend
   - Verify frontend API URL

2. **Build Failures:**
   - Check Node.js version (18+)
   - Verify all dependencies installed

3. **API Timeouts:**
   - Increase function timeout in platform settings
   - Optimize scan parameters

4. **Environment Variables:**
   - Verify all required variables set
   - Check variable names match code

### Debug Commands
```bash
# Test backend locally
python -m uvicorn web_app.backend.main:app --reload

# Test frontend locally
cd web_app/frontend && npm start

# Run all tests
python -m pytest tests/ -v

# Check CLI functionality
python main.py --help
```

---

## 📈 Post-Deployment

### Verification Checklist
- [ ] Frontend loads without errors
- [ ] API endpoints respond correctly
- [ ] Scans can be initiated
- [ ] Reports are generated
- [ ] Downloads work
- [ ] No console errors

### Performance Optimization
- [ ] Enable compression
- [ ] Set up CDN for static assets
- [ ] Optimize bundle size
- [ ] Implement caching

### Maintenance
- [ ] Regular dependency updates
- [ ] Security patches
- [ ] Performance monitoring
- [ ] User feedback collection

---

## 🎯 Next Steps

1. **Domain Setup:** Configure custom domain
2. **SSL Certificate:** Ensure HTTPS is enabled
3. **Backup Strategy:** Set up data backups
4. **Monitoring:** Implement comprehensive monitoring
5. **Documentation:** Create user documentation
6. **Support:** Set up support channels

---

## 📞 Support

For deployment issues:
1. Check platform documentation
2. Review error logs
3. Test locally first
4. Contact platform support if needed

**Happy Deploying! 🚀** 