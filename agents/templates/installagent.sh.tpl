#!/usr/bin/env bash

# Stop on any error
set -euo pipefail

logpath="/home/ubuntu/install/tfeinstall.log" 

mkdir /home/ubuntu/install  | tee -a $logpath

sudo sysctl -w vm.swappiness=1  | tee -a $logpath

function get_secret {
    local secret_id=$1
    /usr/bin/env aws secretsmanager get-secret-value --secret-id $secret_id --region ${region} | jq --raw-output '.SecretBinary,.SecretString | select(. != null)'
}

agent_secret=$(get_secret ${agent_token_id})

sudo echo "TFC_AGENT_TOKEN=$agent_secret" > /etc/tfc-agent.env  | tee -a $logpath
sudo echo "TFC_ADDRESS=https://${tfe_hostname}" >> /etc/tfc-agent.env | tee -a $logpath

echo ${tfcagent_service} | base64 --decode > /home/ubuntu/install/tfc-agent.service | tee -a $logpath

sudo cp /home/ubuntu/install/tfc-agent.service /etc/systemd/system/tfc-agent.service | tee -a $logpath

sudo systemctl daemon-reload  | tee -a $logpath

sudo systemctl enable tfc-agent.service  | tee -a $logpath

sudo systemctl start tfc-agent.service  | tee -a $logpath
