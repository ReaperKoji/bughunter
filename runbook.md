# Runbook (Minimal)

## Essential Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip jq curl
```

## Start Service (Systemd)
```bash
sudo systemctl daemon-reload
sudo systemctl enable automator.service
sudo systemctl start automator.service
sudo systemctl status automator.service
```

## Health Check (cron)
Create `/etc/cron.d/automator-health`:
```cron
*/5 * * * * root /usr/bin/curl -sSf http://127.0.0.1:9108/metrics >/dev/null || /usr/bin/systemctl restart automator.service
```

## Log Rotation (logrotate)
Create `/etc/logrotate.d/automator`:
```conf
/var/log/automator/*.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
```
