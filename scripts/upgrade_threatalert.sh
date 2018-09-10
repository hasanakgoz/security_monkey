#!/usr/bin/env bash
########################################################################################################
# Bash script to automate upgradation of ThreatAlert.
#
# This script assumes that you're going to run ThreatAlert on an Ubuntu EC2 Instance in AWS.
#
# This script will backup the current deployment to ~/threatalert_backup folder, and deploy updates
#
# Written by :: pritam
# Date :: September 2018
#
# Version History ::
#
#
#       0.1 :: 2018/10/18        :: First version submitted to feature/scripts branch
#
# To Do ::
#       1. Create a copy of script and run from temp folder.
#       2. Check for permissions before running the script
#       3. Convert assumptions (such as backup and deployment folders) into variables / input parameters
#       4. Validate Config file restore
#
########################################################################################################

set -e

### Declaring some variables

BACKUP_FOLDER=~/threatalert_backup
DEPLOY_FOLDER=/usr/local/src/security_monkey
[ -z "$SECURITY_MONKEY_SETTINGS" ] && CONFIG_FILE=${SECURITY_MONKEY_SETTINGS} || CONFIG_FILE=${DEPLOY_FOLDER}/env-config/config.py



echo "Stopping stackArmor ThreatAlert Services..."
# Stop ThreatAlert Services
supervisorctl stop securitymonkey
supervisorctl stop securitymonkeyscheduler
service nginx stop

# Store a copy of current configuration file
echo "Making backup of current configuration ($CONFIG_FILE) to ~/"
cp "$CONFIG_FILE" ~/

# Make backup folder if not existing
echo "Creating backup folder.. ${BACKUP_FOLDER}"
[ -d ${BACKUP_FOLDER} ] || mkdir -p ${BACKUP_FOLDER}

# Move Current Installation to Backup Folder
echo "Backing up current installation to ${BACKUP_FOLDER}"
mv /usr/local/src/security_monkey/ ~/security_monkey_backup/`date +%Y%m%d%H%M%S`

# Pull latest version
echo "Fetching latest version from Git"
cd "${DEPLOY_FOLDER}/.."
git clone --depth 1 --branch develop https://github.com/stackArmor/security_monkey.git

# Setup Python Virtual Environment
echo "Setting up Python Virtual Environment"
cd security_monkey
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"
virtualenv venv
source ./venv/bin/activate
pip install --upgrade setuptools

# Install ThreatAlert
echo "Installing ThreatAlert"
python setup.py install

# Build Dart(web) Application
echo "Building Dart(web) Application"
cd /usr/local/src/security_monkey/dart
/usr/lib/dart/bin/pub get
/usr/lib/dart/bin/pub build

# Deploy Web Application
echo "Deploy Web Application"
mkdir -p /usr/local/src/security_monkey/security_monkey/static/
/bin/cp -R /usr/local/src/security_monkey/dart/build/web/* /usr/local/src/security_monkey/security_monkey/static/
chgrp -R www-data /usr/local/src/security_monkey

# Restore Configuration
echo "Restore Config File"
mv ~/config.py /usr/local/src/security_monkey/env-config/

# Upgrade Database if any changes
cd /usr/local/src/security_monkey/
monkey db upgrade

# Enable ThreatAlert Mailers
echo "Deploy stackArmor ThreatAlert Mailers cron"
cp scripts/threatalert.cron.sh /etc/cron.daily/threatalert

# Restart Services
echo "Restart Services"
supervisorctl start securitymonkey
supervisorctl start securitymonkeyscheduler
service nginx start