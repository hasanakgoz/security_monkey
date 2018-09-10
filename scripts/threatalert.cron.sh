#!/usr/bin/env bash
########################################################################################################
# Bash script to automate upgradation of Security Monkey.
#
# This script assumes that you're going to run Security Monkey on an Ubuntu EC2 Instance in AWS.
#
# This script will backup the current deployment to ~/security_monkey_backup folder, and deploy updates
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
#       1.  Create a copy of script and run from temp folder.
#       2.  Check for permissions before running the script
#       3.  Convert assumptions (such as backup and deployment folders) into variables / input parameters
#
########################################################################################################

# Set path to Configuration File
export SECURITY_MONKEY_SETTINGS=/usr/local/src/security_monkey/env-config/config.py
# Activate Python Environment
source /usr/local/src/security_monkey/venv/bin/activate
# Generate and Send Mailers
/usr/local/src/security_monkey/venv/bin/monkey report_mailer
