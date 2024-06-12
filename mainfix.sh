#!/bin/bash

# Telnet check
check_telnet=$(telnet 127.0.0.1 2>/dev/null)
if [ -n "$check_telnet" ]; then
    echo "telnet이 설치되어 있습니다. 원격 접속이 취약할 수 있습니다."

    if [ -f /etc/securetty ]; then
        echo "securetty file이 존재합니다. 패치를 시작합니다."
        sed -i '/^pts\/[0-9]\+$/s/^/#/' /etc/securetty
        echo "/etc/securetty 파일에서 pts/x 설정을 주석 처리했습니다."
    else
        echo "/etc/securetty 파일을 찾을 수 없습니다."
    fi

    if [ -f /etc/pam.d/login ]; then
        echo "/etc/pam.d/login 항목을 발견했습니다. 패치를 시작합니다."
        if grep -q "^#auth required /lib/security/pam_securetty.so" /etc/pam.d/login; then
            sed -i 's|^#auth required /lib/security/pam_securetty.so|auth required /lib/security/pam_securetty.so|' /etc/pam.d/login
            echo "/etc/pam.d/login 파일에서 pam_securetty.so 설정을 활성화했습니다."
        elif ! grep -q "^auth required /lib/security/pam_securetty.so" /etc/pam.d/login; then
            echo "auth required /lib/security/pam_securetty.so" >> /etc/pam.d/login
            echo "/etc/pam.d/login 파일에 pam_securetty.so 설정을 추가했습니다."
        else
            echo "/etc/pam.d/login 파일에서 pam_securetty.so 설정이 이미 활성화되어 있습니다."
        fi
    else
        echo "/etc/pam.d/login 파일을 찾을 수 없습니다."
    fi
else
    echo "telnet이 설치되어 있지 않습니다."

    # pam_securetty.so 설정 확인
    if [ -f /etc/pam.d/login ]; then
        echo "pam_securetty.so 파일을 찾았습니다."
        check_pam=$(grep "pam_securetty.so" /etc/pam.d/login | grep -v "#")
        if [ -n "$check_pam" ]; then
            echo "pam_securetty.so 설정 양호"
        else
            echo "pam_securetty.so 설정 취약"
        fi
    else
        echo "/etc/pam.d/login 파일을 찾을 수 없습니다."
    fi
fi

# SSH check
if [ -f /etc/ssh/sshd_config ]; then
    echo "etc/ssh/sshd_config 파일을 발견하였습니다. 수정을 시작합니다."
    if grep -q "^#PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        echo "PermitRootLogin 설정을 no로 변경했습니다."
    elif grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        echo "PermitRootLogin 설정을 no로 변경했습니다."
    else
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        echo "PermitRootLogin 설정을 추가했습니다."
    fi

    # SSH restart
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd
        echo "SSH 서비스를 재시작했습니다."
    elif command -v service >/dev/null 2>&1; then
        service sshd restart
        echo "SSH 서비스를 재시작했습니다."
    else
        echo "SSH 서비스를 찾을 수 없습니다. 수동 확인 요망."
    fi
else
    echo "/etc/ssh/sshd_config 파일을 찾을 수 없습니다."
fi

# Password check
if [ "$1" = "-fix" ]; then
    password_check_path="/etc/security/pwquality.conf"
    password_setting_content="password requisite pam_cracklib.so try_first_pass retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1"

    if [ -f "$password_check_path" ]; then
        echo "$password_check_path 파일이 존재합니다. 설정이 진행됩니다."

        echo "파일이 존재합니다. 패스워드 복잡성 설정 코드를 작성합니다"
        echo "$password_setting_content" | tee -a "$password_check_path" > /dev/null

        echo "1-2 패스워드 복잡성 설정이 완료되었습니다."
    else
        echo "$password_check_path 파일이 존재하지 않습니다."
        touch "$password_check_path"
        echo "$password_setting_content" | tee "$password_check_path" > /dev/null
        echo "1-2 패스워드 복잡성 설정이 완료되었습니다"
    fi
else
    echo "1-2 패스워드 복잡성 설정을 변경하지 않았습니다."
fi

# Account lockout settings
if [ "$1" = "-fix" ]; then
    account_lockout_setting_path="/etc/pam.d/system-auth"
    account_lockout_setting_pattern="auth required /lib/security/pam_tally.so deny=5 unlock_time=120
    no_magic_root
    account required /lib/security/pam_tally.so no_magic_root reset"

    if grep -q "$account_lockout_setting_pattern" "$account_lockout_setting_path"; then
        echo "변경사항이 없습니다."
    else
        echo "1-3 계정 잠금 임계값이 설정됩니다."
        if [ -f "$account_lockout_setting_path" ]; then
            echo "$account_lockout_setting_pattern" | tee -a "$account_lockout_setting_path" > /dev/null
        else
            touch "$account_lockout_setting_path"
            echo "$account_lockout_setting_pattern" | tee -a "$account_lockout_setting_path" > /dev/null
        fi
    fi
    echo "1-3 계정 잠금 임계값 설정 시, /lib/security/pam_tally.so 파일이 있는지 확인 필요. 해당 라이브러리가 실제 존재하는지 확인 필요."
else
    echo "1-3 계정 잠금 임계값 설정을 변경하지 않았습니다."
fi

# Password file protection
if [ "$1" = "-fix" ]; then
    if [ -f /etc/passwd ]; then
        echo "디렉토리가 존재합니다."

        while IFS=: read -r etc_passwd_user etc_passwd_pass etc_passwd_rest; do
            # 두 번째 필드가 "x"인지 확인
            if [ "$etc_passwd_pass" = "x" ]; then
                echo "정상: $etc_passwd_user"
            else
                echo "수동 진단 요망: $etc_passwd_user"
            fi
        done < /etc/passwd

    else
        echo "etc/passwd 디렉토리 수동 확인 요망"
    fi
else
    echo "Password file protection을 변경하지 않았습니다."
fi

# Root home path directory authority and path settings
if [ "$1" = "-fix" ]; then
    root_home_path_authority=$(which ls)

    if [ "$root_home_path_authority" != "${root_home_path_authority#*.}" ] || [ "$root_home_path_authority" != "${root_home_path_authority%:*}" ]; then
        echo "취약: PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되어 있습니다.수동 확인 요망."
    else
        echo "양호: PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되지 않았습니다."
    fi
else
    echo "Root home path directory authority and path settings을 변경하지 않았습니다."
fi

# File and directory ownership settings
if [ "$1" = "-fix" ]; then
    files_without_owner=$(find / -nouser -o -nogroup -print 2>/dev/null)
    count_files_without_owner=$(echo "$files_without_owner" | wc -l)

    if [ "$count_files_without_owner" -eq 0 ]; then
        echo "양호 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."
    else
        echo "취약 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다."
        echo " 소유자가 존재하지 않는 디렉터리 목록: $files_without_owner"
    fi
else
    echo "File and directory ownership settings을 변경하지 않았습니다."
fi

# /etc/passwd file ownership and permission settings
if [ "$1" = "-fix" ]; then
    passwd_file_path="/etc/passwd"
    file_owner_name=$(stat -c %U "$passwd_file_path")
    file_permissions=$(stat -c %a "$passwd_file_path")

    required_owner="root"
    required_permissions="644"

    if [ "$file_owner_name" = "$required_owner" ] && [ "$file_permissions" -eq "$required_permissions" ]; then
        echo "양호 : /etc/passwd 파일의 소유자가 root이고, 권한이 644입니다."
    else
        echo "취약 : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닙니다. 현재 소유자: $file_owner_name, 현재 권한 : $file_permissions"
    fi
else
    echo "/etc/passwd file ownership and permission settings을 변경하지 않았습니다."
fi

# /etc/shadow file ownership and permission settings
if [ "$1" = "-fix" ]; then
    shadow_file_path="/etc/shadow"
    shadow_file_owner=$(stat -c %U "$shadow_file_path")
    shadow_file_permissions=$(stat -c %a "$shadow_file_path")

    required_owner="root"
    required_permissions="400"

    if [ "$shadow_file_owner" = "$required_owner" ] && [ "$shadow_file_permissions" -le "$required_permissions" ]; then
        echo "양호 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하입니다."
    else
        chown root "$shadow_file_path"
        chmod 400 "$shadow_file_path"
        echo "조치 완료"
    fi
else
    echo "/etc/shadow file ownership and permission settings을 변경하지 않았습니다."
fi

# /etc/hosts file ownership and permission settings
if [ "$1" = "-fix" ]; then
    hosts_file_path="/etc/hosts"
    hosts_file_owner=$(stat -c %U "$hosts_file_path")
    hosts_file_permissions=$(stat -c %a "$hosts_file_path")

    host_required_owner="root"
    host_required_permissions="600"

    if [ "$hosts_file_owner" = "$host_required_owner" ] && [ "$hosts_file_permissions" -le "$host_required_permissions" ]; then
        echo "양호 : /etc/hosts 파일의 소유자가 root이고, 권한이 600 이하입니다."
    else
        echo "취약 : 현재 소유자 : $hosts_file_owner, 현재 권한 : $hosts_file_permissions"
        chown root "$hosts_file_path"
        chmod 600 "$hosts_file_path"
        echo "파일의 소유자를 root로, 권한을 600으로 변경하였습니다."
    fi
else
    echo "/etc/hosts file ownership and permission settings을 변경하지 않았습니다."
fi

# /etc/(x)inetd.conf file ownership and permission settings
if [ "$1" = "-fix" ]; then
    inetd_conf_file="/etc/inetd.conf"
    xinetd_d_directory="/etc/xinetd.d/"

    inetd_conf_file_owner=$(stat -c %U "$inetd_conf_file")
    inetd_conf_file_permissions=$(stat -c %a "$inetd_conf_file")

    inetd_required_owner="root"
    inetd_required_permissions="600"

    if [ "$inetd_conf_file_owner" = "$inetd_required_owner" ] && [ "$inetd_conf_file_permissions" -eq "$inetd_required_permissions" ]; then
        echo "양호 : /etc/inetd.conf 파일의 소유자가 root이고, 권한이 600입니다."
    else
        echo "취약 : 현재 소유자 : $inetd_conf_file_owner 현재 권한 : $inetd_conf_file_permissions"
        chown root "$inetd_conf_file"
        chmod 600 "$inetd_conf_file"
        echo "조치 완료. /etc/inetd.conf 파일의 소유자를 root로, 권한을 600으로 변경하였습니다."
    fi
else
    echo "/etc/(x)inetd.conf file ownership and permission settings을 변경하지 않았습니다."
fi

if [ "$1" = "-fix" ]; then
    echo "모든 조치를 완료했습니다."
else
    echo "조치되지 않은 설정이 있습니다. '-fix' 인자를 추가하여 조치할 수 있습니다."
fi
