# Arvan DNS Failover

A Python script for automatic DNS failover management using ArvanCloud API. This script continuously monitors server status and automatically switches traffic to backup servers in case of main server failure.

🇮🇷 [راهنمای فارسی](README.fa.md)

## Features

- Continuous server monitoring using ping
- Automatic failover to backup server when main server is down
- Telegram notifications with mute/unmute controls
- xray configuration sync between servers
- SSL certificate expiry monitoring
- Certificate folder sync between servers
- Client count monitoring with automatic retry logic
- Panel service restart functionality
- Separate alert types for different issues (capacity, failover, SSL, panel)

## Prerequisites

- Python 3.x
- ArvanCloud API access
- SSH access to servers
- Telegram bot for notifications

## Installation

1. Install required packages:
```bash
pip install -r requirements.txt
```

2. Configure the script:
   - Copy `dns-arvan.py`
   - Set values in `CONFIG` section

## Configuration

Set the following in the `CONFIG` section of the main file:

- `apikey`: ArvanCloud API key
- `domain`: Main domain
- `telegram_bot_token`: Telegram bot token
- `telegram_chat_id`: Telegram chat ID
- Configure each subdomain in the `records` section

## Usage

The script can be run manually or via cron:

```bash
python dns-arvan.py
```

## State Management

State information is stored in `state.json`, which includes:
- Current status of each domain (backup or normal mode)
- Original IPs for restoration
- Last certificate check timestamp
- Mute settings for different alert types (capacity, failover, SSL, panel)

## Alert Types

The system supports different types of alerts with individual mute controls:
- **Capacity Alerts**: When client count exceeds thresholds
- **Failover Alerts**: When DNS failover is activated/restored
- **SSL Alerts**: When SSL certificates are expiring soon
- **Panel Alerts**: When x-ui panel service has issues
