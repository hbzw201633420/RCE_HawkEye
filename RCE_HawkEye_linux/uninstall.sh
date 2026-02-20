#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${RED}"
    echo "  ____  _____  _____   _   _                   _     _____              "
    echo " |  _ \/  __ \|  ___| | | | |                 | |   |  ___|             "
    echo " | |_) | /  \/| |__   | |_| |  __ _ __      __| | __| |__   _   _   ___ "
    echo " |    <| |    |  __|  |  _  | / _\` |\ \ /\ / /| |/ /|  __| | | | | / _ \\"
    echo " | |_) | \__/\| |___  | | | || (_| | \ V  V / |   < | |___ | |_| ||  __/"
    echo " |____/ \____/\____/  \_| |_/ \__,_|  \_/\_/  |_|\_\\____/  \__, ||\___|"
    echo "                                                             __/ |      "
    echo "                                                            |___/       "
    echo -e "${NC}"
    echo -e "${YELLOW}RCE HawkEye Uninstaller${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

find_installation() {
    if [ -f /etc/systemd/system/rce-hawkeye.service ]; then
        SERVICE_FILE="/etc/systemd/system/rce-hawkeye.service"
        INSTALL_DIR=$(grep "WorkingDirectory" "$SERVICE_FILE" | cut -d'=' -f2 | tr -d ' ')
        return 0
    fi
    
    if [ -f /opt/rce-hawkeye/rce-hawkeye ]; then
        INSTALL_DIR="/opt/rce-hawkeye"
        return 0
    fi
    
    if [ -f /opt/RCE_HawkEye/rce-hawkeye ]; then
        INSTALL_DIR="/opt/RCE_HawkEye"
        return 0
    fi
    
    return 1
}

get_user_confirmation() {
    echo -e "${YELLOW}=== Uninstall Options ===${NC}"
    echo ""
    echo "Installation directory: ${CYAN}${INSTALL_DIR}${NC}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"Keep data and configuration? [${NC}Y/n${YELLOW}]: "${NC})" KEEP_DATA
    KEEP_DATA=${KEEP_DATA:-Y}
    
    if [[ "$KEEP_DATA" =~ ^[Yy] ]]; then
        echo -e "${GREEN}Data and configuration will be preserved${NC}"
        KEEP_DATA=true
    else
        echo -e "${RED}All data will be deleted${NC}"
        KEEP_DATA=false
    fi
    echo ""
    
    read -p "$(echo -e ${YELLOW}"Confirm uninstall? [${NC}y/N${YELLOW}]: "${NC})" CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
        echo -e "${RED}Uninstall cancelled${NC}"
        exit 0
    fi
}

stop_service() {
    echo -e "${YELLOW}Stopping service...${NC}"
    
    if systemctl is-active --quiet rce-hawkeye.service 2>/dev/null; then
        systemctl stop rce-hawkeye.service
        echo -e "${GREEN}Service stopped${NC}"
    else
        echo -e "${YELLOW}Service is not running${NC}"
    fi
}

disable_service() {
    echo -e "${YELLOW}Disabling service...${NC}"
    
    if systemctl is-enabled --quiet rce-hawkeye.service 2>/dev/null; then
        systemctl disable rce-hawkeye.service
        echo -e "${GREEN}Service disabled${NC}"
    fi
    
    if [ -f /etc/systemd/system/rce-hawkeye.service ]; then
        rm -f /etc/systemd/system/rce-hawkeye.service
        systemctl daemon-reload
        echo -e "${GREEN}Service file removed${NC}"
    fi
}

remove_binary_link() {
    echo -e "${YELLOW}Removing binary link...${NC}"
    
    if [ -L /usr/local/bin/rce-hawkeye ]; then
        rm -f /usr/local/bin/rce-hawkeye
        echo -e "${GREEN}Binary link removed${NC}"
    fi
}

backup_data() {
    if [ "$KEEP_DATA" = true ]; then
        BACKUP_DIR="/opt/rce-hawkeye-backup-$(date +%Y%m%d_%H%M%S)"
        echo -e "${YELLOW}Backing up data to ${BACKUP_DIR}...${NC}"
        
        mkdir -p "$BACKUP_DIR"
        
        if [ -d "${INSTALL_DIR}/configs" ]; then
            cp -r "${INSTALL_DIR}/configs" "$BACKUP_DIR/"
        fi
        
        if [ -d "${INSTALL_DIR}/data/history" ]; then
            mkdir -p "$BACKUP_DIR/data"
            cp -r "${INSTALL_DIR}/data/history" "$BACKUP_DIR/data/"
        fi
        
        echo -e "${GREEN}Data backed up to ${BACKUP_DIR}${NC}"
    fi
}

remove_files() {
    echo -e "${YELLOW}Removing files...${NC}"
    
    if [ -d "$INSTALL_DIR" ]; then
        if [ "$KEEP_DATA" = true ]; then
            rm -f "${INSTALL_DIR}/rce-hawkeye"
            rm -f "${INSTALL_DIR}/run.sh"
            rm -f "${INSTALL_DIR}/install.sh"
            rm -f "${INSTALL_DIR}/Dockerfile"
            rm -f "${INSTALL_DIR}/docker-compose.yml"
            rm -f "${INSTALL_DIR}/README.md"
            rm -f "${INSTALL_DIR}/LICENSE"
            rm -f "${INSTALL_DIR}/.gitignore"
            rm -rf "${INSTALL_DIR}/reports"
            echo -e "${GREEN}Program files removed, data preserved${NC}"
        else
            rm -rf "$INSTALL_DIR"
            echo -e "${GREEN}All files removed${NC}"
        fi
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     Uninstall Completed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    if [ "$KEEP_DATA" = true ]; then
        echo -e "Data backup location: ${CYAN}${BACKUP_DIR}${NC}"
        echo ""
        echo "To reinstall:"
        echo "  1. Download the new version"
        echo "  2. Copy configs and data from backup"
        echo "  3. Run install.sh"
    fi
    echo ""
}

main() {
    print_banner
    check_root
    
    if ! find_installation; then
        echo -e "${RED}RCE HawkEye installation not found${NC}"
        exit 1
    fi
    
    get_user_confirmation
    stop_service
    disable_service
    remove_binary_link
    backup_data
    remove_files
    print_summary
}

main "$@"
