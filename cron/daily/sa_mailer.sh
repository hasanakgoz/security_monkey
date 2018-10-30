#!/bin/sh
# Daily ThreatAlert Report Mailer
# stackArmor

export SECURITY_MONKEY_SETTINGS=/usr/local/src/security_monkey/env-config/config.py
source /usr/local/src/security_monkey/venv/bin/activate
/usr/local/src/security_monkey/venv/bin/monkey report_mailer