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
git clone https://github.com/RichSsa24/Sentinel_Linux.git
cd Sentinel_Linux

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
git clone https://github.com/RichSsa24/Sentinel_Linux.git
cd Sentinel_Linux
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
sudo mkdir -p /etc/Sentinel_Linux

# Copy default configuration
sudo cp src/config/default_config.yaml /etc/Sentinel_Linux/config.yaml

# Set permissions
sudo chmod 750 /etc/Sentinel_Linux
sudo chmod 640 /etc/Sentinel_Linux/config.yaml
```

#### Step 5: Create Log Directory

```bash
# Create log directory
sudo mkdir -p /var/log/Sentinel_Linux

# Set permissions
sudo chmod 750 /var/log/Sentinel_Linux
```

#### Step 6: Create Data Directory

```bash
# Create data directories
sudo mkdir -p /var/lib/Sentinel_Linux/{baselines,cache}

# Set permissions
sudo chmod 750 /var/lib/Sentinel_Linux
```

### Method 3: Development Installation

```bash
# Clone repository
git clone https://github.com/RichSsa24/Sentinel_Linux.git
cd Sentinel_Linux

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

Edit `/etc/Sentinel_Linux/config.yaml`:

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
sudo chown -R security-monitor:security-monitor /var/lib/Sentinel_Linux
sudo chown -R security-monitor:security-monitor /var/log/Sentinel_Linux

# Add to required groups for log access
sudo usermod -aG adm security-monitor
```

### Systemd Service Setup

Create `/etc/systemd/system/Sentinel_Linux.service`:

```ini
[Unit]
Description=Sentinel Linux Security Monitor
Documentation=https://github.com/RichSsa24/Sentinel_Linux
After=network.target syslog.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/Sentinel_Linux/venv/bin/python -m src.cli.main run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=Sentinel_Linux

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/log/Sentinel_Linux /var/lib/Sentinel_Linux

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable Sentinel_Linux
sudo systemctl start Sentinel_Linux
sudo systemctl status Sentinel_Linux
```

**Alternative: Using the control script**

```bash
# Start the monitor
sudo ./scripts/bash/run_monitor.sh start

# Check status
sudo ./scripts/bash/run_monitor.sh status

# Stop the monitor
sudo ./scripts/bash/run_monitor.sh stop
```

## Verification

### Verify Installation

```bash
# Check Python installation
python3 --version

# Check package installation
pip show Sentinel_Linux

# Test configuration
python -m src.cli.main config validate
```

### Run Quick Test

```bash
# Run with verbose output
sudo python -m src.cli.main run --log-level DEBUG --dry-run

# Run system audit script
sudo ./scripts/bash/system_audit.sh
```

### Check Logs

```bash
# Check service logs
sudo journalctl -u Sentinel_Linux -f

# Check application logs
sudo tail -f /var/log/Sentinel_Linux/monitor.log
```

## Troubleshooting

### Common Issues

#### Permission Denied Errors

```bash
# Check if running with sufficient privileges
sudo python -m src.cli.main run

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
python -m src.cli.main config validate

# Check YAML syntax
python -c "import yaml; yaml.safe_load(open('/etc/Sentinel_Linux/config.yaml'))"
```

#### Service Won't Start

```bash
# Check service status
sudo systemctl status Sentinel_Linux

# Check for errors in journal
sudo journalctl -u Sentinel_Linux --no-pager -n 50

# Test manually
sudo /opt/Sentinel_Linux/venv/bin/python -m src.cli.main run

# Or use the control script
sudo ./scripts/bash/run_monitor.sh foreground
```

### Getting Help

1. Check the [Usage Guide](USAGE.md)
2. Search existing [GitHub Issues](https://github.com/RichSsa24/Sentinel_Linux/issues)
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
sudo systemctl stop Sentinel_Linux
sudo systemctl disable Sentinel_Linux

# Remove service file
sudo rm /etc/systemd/system/Sentinel_Linux.service
sudo systemctl daemon-reload

# Remove directories
sudo rm -rf /opt/Sentinel_Linux
sudo rm -rf /etc/Sentinel_Linux
sudo rm -rf /var/log/Sentinel_Linux
sudo rm -rf /var/lib/Sentinel_Linux

# Remove service account
sudo userdel security-monitor
```

## Upgrading

### From Previous Version

```bash
# Stop service
sudo systemctl stop Sentinel_Linux

# Backup configuration
sudo cp /etc/Sentinel_Linux/config.yaml /etc/Sentinel_Linux/config.yaml.bak

# Update repository
cd /opt/Sentinel_Linux
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -e . --upgrade

# Check for configuration changes
diff src/config/default_config.yaml /etc/Sentinel_Linux/config.yaml

# Restart service
sudo systemctl start Sentinel_Linux
```

## Security Considerations

- Run with minimum required privileges
- Protect configuration files containing sensitive data
- Use TLS for webhook notifications
- Regularly update dependencies for security patches
- Review [SECURITY.md](../SECURITY.md) for complete security guidance



