#!/bin/bash

RCE_HAWKEYE_VERSION="1.1.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR=""
SERVICE_PORT=""
BIN_DIR="/usr/local/bin"

print_banner() {
    echo -e "${CYAN}"
    echo "  ____  _____  _____   _   _                   _     _____              "
    echo " |  _ \/  __ \|  ___| | | | |                 | |   |  ___|             "
    echo " | |_) | /  \/| |__   | |_| |  __ _ __      __| | __| |__   _   _   ___ "
    echo " |    <| |    |  __|  |  _  | / _\` |\ \ /\ / /| |/ /|  __| | | | | / _ \\"
    echo " | |_) | \__/\| |___  | | | || (_| | \ V  V / |   < | |___ | |_| ||  __/"
    echo " |____/ \____/\____/  \_| |_/ \__,_|  \_/\_/  |_|\_\\____/  \__, ||\___|"
    echo "                                                             __/ |      "
    echo "                                                            |___/       "
    echo -e "${NC}"
    echo -e "${YELLOW}RCE HawkEye Installer v${RCE_HAWKEYE_VERSION}${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

get_user_input() {
    echo -e "${GREEN}=== Configuration ===${NC}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"Enter installation directory [${NC}/opt/rce-hawkeye${YELLOW}]: "${NC})" INSTALL_DIR
    INSTALL_DIR=${INSTALL_DIR:-/opt/rce-hawkeye}
    
    while true; do
        read -p "$(echo -e ${YELLOW}"Enter service port [${NC}8080${YELLOW}]: "${NC})" SERVICE_PORT
        SERVICE_PORT=${SERVICE_PORT:-8080}
        
        if [[ "$SERVICE_PORT" =~ ^[0-9]+$ ]] && [ "$SERVICE_PORT" -ge 1 ] && [ "$SERVICE_PORT" -le 65535 ]; then
            break
        else
            echo -e "${RED}Invalid port number. Please enter a valid port (1-65535).${NC}"
        fi
    done
    
    echo ""
    echo -e "${GREEN}=== Summary ===${NC}"
    echo -e "  Installation Directory: ${CYAN}${INSTALL_DIR}${NC}"
    echo -e "  Service Port: ${CYAN}${SERVICE_PORT}${NC}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"Continue with installation? [${NC}Y/n${YELLOW}]: "${NC})" CONFIRM
    CONFIRM=${CONFIRM:-Y}
    
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 0
    fi
    echo ""
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y curl
    elif command -v yum &> /dev/null; then
        yum install -y curl
    elif command -v dnf &> /dev/null; then
        dnf install -y curl
    fi
    
    echo -e "${GREEN}Dependencies installed${NC}"
}

stop_old_service() {
    echo -e "${YELLOW}Checking for existing service...${NC}"
    
    if systemctl is-active --quiet rce-hawkeye.service 2>/dev/null; then
        echo -e "${YELLOW}Stopping existing service...${NC}"
        systemctl stop rce-hawkeye.service
    fi
    
    if systemctl is-enabled --quiet rce-hawkeye.service 2>/dev/null; then
        systemctl disable rce-hawkeye.service
    fi
    
    if [ -f /etc/systemd/system/rce-hawkeye.service ]; then
        rm -f /etc/systemd/system/rce-hawkeye.service
        systemctl daemon-reload
    fi
    
    echo -e "${GREEN}Old service cleaned up${NC}"
}

install_binary() {
    echo -e "${YELLOW}Installing RCE HawkEye...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    mkdir -p ${INSTALL_DIR}
    mkdir -p ${INSTALL_DIR}/configs
    mkdir -p ${INSTALL_DIR}/data/dict
    mkdir -p ${INSTALL_DIR}/data/history
    mkdir -p ${INSTALL_DIR}/reports
    
    cp ${SCRIPT_DIR}/rce-hawkeye ${INSTALL_DIR}/
    if [ -d ${SCRIPT_DIR}/configs ]; then
        cp -r ${SCRIPT_DIR}/configs/* ${INSTALL_DIR}/configs/
    fi
    if [ -d ${SCRIPT_DIR}/data/dict ]; then
        cp -r ${SCRIPT_DIR}/data/dict/* ${INSTALL_DIR}/data/dict/
    fi
    
    chmod +x ${INSTALL_DIR}/rce-hawkeye
    
    ln -sf ${INSTALL_DIR}/rce-hawkeye ${BIN_DIR}/rce-hawkeye
    
    echo -e "${GREEN}RCE HawkEye installed to ${INSTALL_DIR}${NC}"
}

create_systemd_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/rce-hawkeye.service << EOF
[Unit]
Description=RCE HawkEye Web Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/rce-hawkeye web -p ${SERVICE_PORT}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable rce-hawkeye
    
    echo -e "${GREEN}Systemd service created${NC}"
}

configure_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    if command -v firewall-cmd &> /dev/null; then
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port=${SERVICE_PORT}/tcp 2>/dev/null
            firewall-cmd --reload 2>/dev/null
            echo -e "${GREEN}Firewall configured for port ${SERVICE_PORT}${NC}"
        else
            echo -e "${YELLOW}Firewalld is not running, skipping firewall configuration${NC}"
        fi
    else
        echo -e "${YELLOW}firewall-cmd not found, skipping firewall configuration${NC}"
    fi
}

start_service() {
    echo -e "${YELLOW}Starting service...${NC}"
    systemctl start rce-hawkeye
    sleep 2
    
    if systemctl is-active --quiet rce-hawkeye.service; then
        echo -e "${GREEN}Service started successfully${NC}"
    else
        echo -e "${RED}Service failed to start. Check logs with: journalctl -u rce-hawkeye -n 50${NC}"
        exit 1
    fi
}

print_success() {
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     Installation Completed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Installation Directory: ${CYAN}${INSTALL_DIR}${NC}"
    echo -e "Service Port: ${CYAN}${SERVICE_PORT}${NC}"
    echo ""
    echo -e "${YELLOW}Access Web Interface:${NC}"
    echo -e "  http://localhost:${SERVICE_PORT}"
    echo -e "  http://${LOCAL_IP}:${SERVICE_PORT}"
    echo ""
    echo -e "${YELLOW}CLI Usage:${NC}"
    echo -e "  rce-hawkeye -h                    Show help"
    echo -e "  rce-hawkeye web -p ${SERVICE_PORT}          Start web service"
    echo -e "  rce-hawkeye -u http://example.com Scan URL"
    echo ""
    echo -e "${YELLOW}Systemd Commands:${NC}"
    echo -e "  systemctl start rce-hawkeye       Start service"
    echo -e "  systemctl stop rce-hawkeye        Stop service"
    echo -e "  systemctl restart rce-hawkeye     Restart service"
    echo -e "  systemctl status rce-hawkeye      Check status"
    echo -e "  journalctl -u rce-hawkeye -f      View logs"
    echo ""
}

main() {
    print_banner
    check_root
    get_user_input
    install_dependencies
    stop_old_service
    install_binary
    create_systemd_service
    configure_firewall
    start_service
    print_success
}

main "$@"
