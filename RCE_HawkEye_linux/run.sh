#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

show_help() {
    echo ""
    echo "  ____  _____  _____   _   _                   _     _____              "
    echo " |  _ \/  __ \|  ___| | | | |                 | |   |  ___|             "
    echo " | |_) | /  \/| |__   | |_| |  __ _ __      __| | __| |__   _   _   ___ "
    echo " |    <| |    |  __|  |  _  | / _\` |\ \ /\ / /| |/ /|  __| | | | | / _ \\"
    echo " | |_) | \__/\| |___  | | | || (_| | \ V  V / |   < | |___ | |_| ||  __/"
    echo " |____/ \____/\____/  \_| |_/ \__,_|  \_/\_/  |_|\_\\____/  \__, ||\___|"
    echo "                                                             __/ |      "
    echo "                                                            |___/       "
    echo ""
    echo "                    R C E 鹰 眼 v1.1.1"
    echo ""
    echo "Usage:"
    echo "  $0 web              Start web service"
    echo "  $0 -u URL           Scan single URL"
    echo "  $0 -f FILE          Scan from file"
    echo "  $0 -h               Show help"
    echo ""
    echo "Examples:"
    echo "  $0 web -p 8080"
    echo "  $0 -u 'http://example.com/api?cmd=test'"
    echo ""
}

if [ $# -eq 0 ]; then
    show_help
    read -p "Press Enter to exit..."
    exit 0
fi

./rce-hawkeye "$@"
