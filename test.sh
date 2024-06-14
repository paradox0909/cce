#!/bin/bash

# /etc/syslog.conf file owner authority setting
etc_syslog_conf_path="/etc/syslog.conf"

if [ ! -f "$etc_syslog_conf_path" ]; then
    echo "$etc_syslog_conf_path 파일이 존재하지 않습니다."
else
    syslog_conf_file_owner=$(stat -c %U "$etc_syslog_conf_path")
    syslog_conf_file_permissions=$(stat -c %a "$etc_syslog_conf_path")
    syslog_acceptable_owners=("root" "bin" "sys")
    required_syslog_permissions=640

    is_owner_acceptable() {
        local input_owner=$1
        for acceptable_owner in "${syslog_acceptable_owners[@]}"; do
            if [ "$input_owner" = "$acceptable_owner" ]; then
                return 0
            fi
        done
        return 1
    }

    if is_owner_acceptable "$syslog_conf_file_owner" && [ "$syslog_conf_file_permissions" -le "$required_syslog_permissions" ]; then
        echo "양호 : /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하입니다."
    else
        echo "취약 : 현재 소유자 : $syslog_conf_file_owner, 현재 권한 : $syslog_conf_file_permissions"
        echo "/etc/syslog.conf 파일 소유자 및 권한 설정 수동 진단 필요 요망."
    fi

    if [ "$1" = "-fix" ]; then
        echo "-fix 인자값에 따라 조치를 시작합니다."
        ls -l /etc/syslog.conf
        if ! is_owner_acceptable "$syslog_conf_file_owner" || [ "$syslog_conf_file_permissions" -gt "$required_syslog_permissions" ]; then
            echo "\"syslog.conf\" 파일 소유자가 root, bin, sys가 아니거나 파일의 권한이 640이 아닙니다."
            echo "소유자를 root로, 권한을 640으로 변경합니다."
            chown root /etc/syslog.conf
            chmod 640 /etc/syslog.conf
            echo "/etc/syslog.conf 파일 소유자 및 권한을 설정했습니다."
        else
            echo "소유자가 root(또는 bin, sys)이고, 파일의 권한이 640 이하입니다. 변경사항이 없습니다."
        fi
    fi
fi
