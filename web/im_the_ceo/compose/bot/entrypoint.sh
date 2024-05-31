#!/bin/sh
# entrypoint.sh

# Resolve the IP address of the 'app' service
APP_IP=$(getent hosts app_ceo | awk '{ print $1 }')
echo "executing entrypoint"
# Export the IP address as APPHOST
export APPHOST=$APP_IP
echo "the app host is ${APPHOST}"
export APPURL="http://$APPHOST:8080"
# Start the bot application (replace this with the actual command to start your bot)
exec node /home/bot/index.js
