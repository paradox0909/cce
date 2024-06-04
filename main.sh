#!/bin/sh
apt-get update
        echo "apt-get has updated."
#1-1-1 telnet check
check_telnet=$(telnet 127.0.0.1 2>/dev/null)
if [ -n "$check_telnet" ]; then
    echo "telnet이 설치되어 있습니다. 원격 접속이 취약할 수 있습니다."

    if [ -f /etc/securetty ]; then
        sed -i '/^pts\/[0-9]\+$/s/^/#/' /etc/securetty
        echo "/etc/securetty 파일에서 pts/x 설정을 주석 처리했습니다."
    else
        echo "/etc/securetty 파일을 찾을 수 없습니다."
    fi

    if [ -f /etc/pam.d/login ]; then
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

#1-1-2 ssh check
if [ -f /etc/ssh/sshd_config ]; then
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

    # ssh restart
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
#1-2 password check

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

#1-3 Set account lockout settings
apt-get install libpam-pwquality -y
apt-get install libpam-pwquality -y
echo "libpam-pwquality 패키지가 설치되었습니다. 작업을 진행합니다."

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
#1-4 password file protect
