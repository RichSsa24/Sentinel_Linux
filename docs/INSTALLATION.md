# Installation Guide

## System Requirements

### Supported Operating Systems
- Red Hat Enterprise Linux 8+ / CentOS Stream 8+
- Debian 10+ (Buster and later)
- Ubuntu 20.04 LTS and later
- Fedora 35+
- Amazon Linux 2023

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 512 MB | 2 GB |
| Disk | 100 MB | 1 GB (for logs/baselines) |

### Software Dependencies

- Python 3.9 or higher
- pip 21.0 or higher
- Root/sudo access for full monitoring capabilities

### Optional Dependencies

- `yara` library (for YARA rule support)
- `libcap` (for capability-based privilege management)

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-security-monitor.git
cd linux-security-monitor

# Run the installation script
chmod +x scripts/bash/install.sh
sudo ./scripts/bash/install.sh
```

The install script will:
1. Check system requirements
2. Install Python dependencies
3. Create configuration directories
4. Set up systemd service (optional)
5. Create dedicated service account

### Method 2: Manual Installation

#### Step 1: Clone Repository

```bash
git clone https://github.com/RichSsa24/linux-security-monitor.git
cd linux-security-monitor
```

#### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

#### Step 3: Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Or install as editable package
pip install -e .

# For development
pip install -e ".[dev]"

# For YARA support (requires libyara)
pip install -e ".[yara]"
```

#### Step 4: Create Configuration Directory

```bash
# Create configuration directory
sudo mkdir -p /etc/linux-security-monitor

# Copy default configuration
sudo cp src/config/default_config.yaml /etc/linux-security-monitor/config.yaml

# Set permissions
sudo chmod 750 /etc/linux-security-monitor
sudo chmod 640 /etc/linux-security-monitor/config.yaml
```

#### Step 5: Create Log Directory

```bash
# Create log directory
sudo mkdir -p /var/log/linux-security-monitor

# Set permissions
sudo chmod 750 /var/log/linux-security-monitor
```

#### Step 6: Create Data Directory

```bash
# Create data directories
sudo mkdir -p /var/lib/linux-security-monitor/{baselines,cache}

# Set permissions
sudo chmod 750 /var/lib/linux-security-monitor
```

### Method 3: Development Installation

```bash
# Clone repository
git clone https://github.com/yourusername/linux-security-monitor.git
cd linux-security-monitor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies including dev tools
pip install -e ".[all]"

# Install pre-commit hooks
pre-commit install

# Verify installation
pytest tests/ -v
```

## Post-Installation Configuration

### Basic Configuration

Edit `/etc/linux-security-monitor/config.yaml`:

```yaml
# Monitoring configuration
monitors:
  user_monitor:
    enabled: true
    poll_interval: 60
  
  process_monitor:
    enabled: true
    poll_interval: 30
    
  network_monitor:
    enabled: true
    poll_interval: 30
    
  file_integrity_monitor:
    enabled: true
    watched_paths:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers
      - /etc/ssh/sshd_config

# Alert configuration
alerting:
  severity_threshold: LOW
  deduplication_window: 300

# Reporting configuration
reporters:
  console:
    enabled: true
    
  json:
    enabled: true
    output_path: /var/log/linux-security-monitor/events.json
    
  syslog:
    enabled: false
    facility: LOCAL0
    
  webhook:
    enabled: false
    url: ""
```

### Service Account Setup (Recommended)

```bash
# Create dedicated service account
sudo useradd -r -s /sbin/nologin -d /var/lib/linux-security-monitor security-monitor

# Set ownership
sudo chown -R security-monitor:security-monitor /var/lib/linux-security-monitor
sudo chown -R security-monitor:security-monitor /var/log/linux-security-monitor

# Add to required groups for log access
sudo usermod -aG adm security-monitor
```

### Systemd Service Setup

Create `/etc/systemd/system/linux-security-monitor.service`:

```ini
[Unit]
Description=Linux Security Monitor
Documentation=https://github.com/yourusername/linux-security-monitor
After=network.target syslog.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/linux-security-monitor/venv/bin/python /opt/linux-security-monitor/scripts/python/run_monitor.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=linux-security-monitor

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/log/linux-security-monitor /var/lib/linux-security-monitor

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable linux-security-monitor
sudo systemctl start linux-security-monitor
sudo systemctl status linux-security-monitor
```

## Verification

### Verify Installation

```bash
# Check Python installation
python3 --version

# Check package installation
pip show linux-security-monitor

# Run self-test
python -m src.core.selftest

# Test configuration
python scripts/python/run_monitor.py --config-test
```

### Run Quick Test

```bash
# Run with verbose output
sudo python scripts/python/run_monitor.py --verbose --dry-run

# Run system audit script
sudo ./scripts/bash/system_audit.sh
```

### Check Logs

```bash
# Check service logs
sudo journalctl -u linux-security-monitor -f

# Check application logs
sudo tail -f /var/log/linux-security-monitor/monitor.log
```

## Troubleshooting

### Common Issues

#### Permission Denied Errors

```bash
# Check if running with sufficient privileges
sudo python scripts/python/run_monitor.py

# Or grant specific capabilities
sudo setcap cap_net_admin,cap_sys_ptrace+ep $(which python3)
```

#### Missing Dependencies

```bash
# Install system dependencies on Debian/Ubuntu
sudo apt-get install python3-dev libffi-dev

# Install system dependencies on RHEL/CentOS
sudo dnf install python3-devel libffi-devel
```

#### Configuration Errors

```bash
# Validate configuration
python scripts/python/run_monitor.py --validate-config

# Check YAML syntax
python -c "import yaml; yaml.safe_load(open('/etc/linux-security-monitor/config.yaml'))"
```

#### Service Won't Start

```bash
# Check service status
sudo systemctl status linux-security-monitor

# Check for errors in journal
sudo journalctl -u linux-security-monitor --no-pager -n 50

# Test manually
sudo /opt/linux-security-monitor/venv/bin/python /opt/linux-security-monitor/scripts/python/run_monitor.py
```

### Getting Help

1. Check the [FAQ](FAQ.md)
2. Search existing [GitHub Issues](https://github.com/yourusername/linux-security-monitor/issues)
3. Open a new issue with:
   - System information (`uname -a`, `python3 --version`)
   - Installation method used
   - Full error message/stack trace
   - Configuration file (sanitized)

## Uninstallation

### Remove Package

```bash
# Deactivate virtual environment
deactivate

# Stop and disable service
sudo systemctl stop linux-security-monitor
sudo systemctl disable linux-security-monitor

# Remove service file
sudo rm /etc/systemd/system/linux-security-monitor.service
sudo systemctl daemon-reload

# Remove directories
sudo rm -rf /opt/linux-security-monitor
sudo rm -rf /etc/linux-security-monitor
sudo rm -rf /var/log/linux-security-monitor
sudo rm -rf /var/lib/linux-security-monitor

# Remove service account
sudo userdel security-monitor
```

## Upgrading

### From Previous Version

```bash
# Stop service
sudo systemctl stop linux-security-monitor

# Backup configuration
sudo cp /etc/linux-security-monitor/config.yaml /etc/linux-security-monitor/config.yaml.bak

# Update repository
cd /opt/linux-security-monitor
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -e . --upgrade

# Check for configuration changes
diff src/config/default_config.yaml /etc/linux-security-monitor/config.yaml

# Restart service
sudo systemctl start linux-security-monitor
```

## Security Considerations

- Run with minimum required privileges
- Protect configuration files containing sensitive data
- Use TLS for webhook notifications
- Regularly update dependencies for security patches
- Review [SECURITY.md](../SECURITY.md) for complete security guidance



