#!/bin/bash

check_tmout() {
    local profile_file="/etc/profile"
    local current_tmout=$(grep -E '^TMOUT=' "$profile_file" | awk -F= '{print $2}')
    
    if [ -z "$current_tmout" ]; then
        echo "TMOUT 값이 설정되어 있지 않습니다. 기본값이 필요합니다."
        current_tmout=0
    fi

    if [ "$current_tmout" -le 600 ]; then
        echo "양호"
    else
        echo "취약"
    fi
}

set_tmout() {
    local profile_file="/etc/profile"
    
    if ! grep -q '^TMOUT=' "$profile_file"; then
        echo "TMOUT=600" >> "$profile_file"
        echo "export TMOUT" >> "$profile_file"
        echo "TMOUT 값을 600초로 설정했습니다."
    else
        echo "TMOUT 값이 이미 설정되어 있습니다."
    fi
}

check_tmout
# set_tmout
