#!/bin/sh

# apt update
# echo "apt 저장소를 업데이트 하였습니다."
echo "libpam-pwquality 패키지를 설치할까요?"
echo "참고 : libpam-pwquality 패키지는 비밀번호 유효성과 품질 규칙을 효과적으로 도와주는 저장소입니다."
echo "서버에 설치를 원하시면 [Y/y], 서버에 설치를 원하지 않으시면 [N/n]을 입력해주세요."
read -r package_answer
package_answer=$(echo "$package_answer" | tr '[:upper:]' '[:lower:]')

if [ "$package_answer" = "y" ]; then
    echo "libpam-pwquality 패키지 설치가 시작됩니다."
    sudo apt-get install libpam-pwquality -y
    echo "설치가 완료되었습니다."
elif [ "$package_answer" = "n" ]; then
    echo "libpam-pwquality 설치를 중단합니다. 검사 및 조치가 재개됩니다."
else
    echo "잘못된 입력값입니다."
    exit 1
fi

# 1-1-1 telnet check
check_telnet=$(telnet 127.0.0.1 2>/dev/null)
if [ -n "$check_telnet" ]; then
    echo "telnet이 설치되어 있습니다. 원격 접속이 취약할 수 있습니다."

    if [ "$1" = "-fix" ]; then
        if [ -f /etc/securetty ]; then
            echo "telnet Securetty 파일이 존재합니다."
            echo "[+] -fix 인자값에 따라 패치가 진행됩니다."
            sed -i '/^pts\/[0-9]\+$/s/^/#/' /etc/securetty
            echo "/etc/securetty 파일에서 pts/x 설정을 주석 처리했습니다."
        fi
    fi
fi

# 1-1-2 ssh check
if [ -f /etc/ssh/sshd_config ]; then
    echo "/etc/ssh/sshd_config 파일을 발견했습니다."
    echo "ssh 접속이 취약할 수 있습니다."

    if [ "$1" = "-fix" ]; then
        echo "ssh /etc/ssh/sshd_config 파일이 존재합니다."
        echo "-fix 인자값에 따라 패치가 진행됩니다."
        if grep -q "^#PermitRootLogin" /etc/ssh/sshd_config; then
            sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            echo "PermitRootLogin 설정을 no로 변경했습니다."
        else
            echo "PermitRootLogin no" >> /etc/ssh/sshd_config
            echo "PermitRootLogin 설정을 추가했습니다."
        fi
    fi
fi

# 1-2 password check
password_check_path="/etc/security/pwquality.conf"
password_setting_content="password requisite pam_cracklib.so try_first_pass retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1"

if [ -f "$password_check_path" ]; then
    echo "$password_check_path 파일이 존재합니다."
    echo "비밀번호 설정 점검 요망"

    if [ "$1" = "-fix" ]; then
        echo "-fix 인자값에 따라 패치가 진행됩니다."
        echo "$password_check_path 비밀번호 설정을 추가합니다."
        echo "패스워드 복잡성 설정 코드를 작성합니다."
        echo "$password_setting_content" | tee -a "$password_check_path" > /dev/null
        echo "패스워드 복잡성 설정 코드를 작성 및 설정하였습니다."
    fi
else
    echo "$password_check_path 파일이 존재하지 않습니다."
    touch "$password_check_path"
    echo "$password_check_path 디렉터리를 생성했습니다."
    echo "-fix 인자값에 따라 패치가 계속됩니다..."
    echo "$password_setting_content" | tee "$password_check_path" > /dev/null
    echo "패스워드 복잡성 설정이 완료되었습니다."
fi

# 1-3 Set account lockout settings
account_lockout_setting_path="/etc/pam.d/system-auth"
account_lockout_setting_pattern="auth required /lib/security/pam_tally.so deny=5 unlock_time=120
no_magic_root
account required /lib/security/pam_tally.so no_magic_root reset"

if grep -q "$account_lockout_setting_pattern" "$account_lockout_setting_path"; then
    echo "계정 잠금 임계값 설정이 안전합니다."
    echo "변경사항이 없습니다."
else
    echo "$account_lockout_setting_path 수동 확인 요망."

    if [ "$1" = "-fix" ]; then
        echo "-fix 인자에 따라 패치가 계속됩니다."
        if [ -f "$account_lockout_setting_path" ]; then
            echo "$account_lockout_setting_pattern" | tee -a "$account_lockout_setting_path" > /dev/null
            echo "계정 잠금 임계값 설정이 완료되었습니다."
        else
            touch "$account_lockout_setting_path"
            echo "$account_lockout_setting_pattern" | tee -a "$account_lockout_setting_path" > /dev/null
            echo "계정 잠금 임계값 설정이 완료되었습니다."
        fi
    fi
fi
echo "1-3 계정 잠금 임계값 설정 시,"
echo "/lib/security/pam_tally.so 파일이 있는지 >확인 필요. 해당 라이브러리가 실제 존재하는지 확인 필요."

#1-4 password file protect
if [ -f /etc/passwd ]; then
    echo "/etc/passwd 디렉터리가 존재합니다."

    while IFS=: read -r etc_passwd_user etc_passwd_pass etc_passwd_rest; do
    if [ "$etc_passwd_pass" = "x" ]; then
        echo "정상 : $etc_passwd_user"
    else
        echo "수동 진단 요밍: $etc_passwd_user"
    fi
    done < /etc/passwd

else
    echo "/etc/passwd 디렉토리 수동 확인 요망"
fi
if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 패치가 진행됩니다... "
    pwconv
    pwunconv
    echo "쉐도우 패스워드 정책을 적용했습니다."
fi

#2-1 root 홈 패스 디렉터리 권한 및 패스 설정
root_home_path_authority=$(which ls)

if [ "$root_home_path_authority" != "${root_home_path_authority#*.}" ] || [ "$root_home_path_authority" != "${root_home_path_authority%:*}" ]; then
    echo "취약: PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되어 있습니다. 수동 확인 요망."
else
    echo "양호 : PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되지 않았습니다. 수동 확인 요망."
fi

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 패치가 진행됩니다... "
    echo "PATH =.:$PATH:$HOME/bin"
    sed -i 's|^PATH =.:$PATH:$HOME/bin|PATH =$PATH:$HOME/bin:.|' ~/.profile
    echo "~/.profile 파일을 수정하였습니다. "

    echo "PATH =.:$PATH:$HOME/bin"
    sed -i 's|^PATH =.:$PATH:$HOME/bin|PATH =$PATH:$HOME/bin:.|' /etc/profile
    echo "/etc/profile 파일을 수정하였습니다. "
fi

#2-2 파일 및 디렉터리 소유자 설정
files_without_owner=$(find / -nouser -o -nogroup -print 2>/dev/null)
count_files_without_owner=$(echo "$files_without_owner" | wc -l)

if [ "$count_files_without_owner" -eq 0 ]; then
    echo "양호 : 소유자가 존재하지 안흔ㄴ 파일 및 디렉터리가 존재하지 않습니다. "
else 
    echo "취약 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다. "
    echo "소유자가 존재하지 않는 디렉토리 목록 : $files_without_owner"
    echo "수동 점검 진단 요망. "
fi

echo "소유자가 없는 파일 및 그룹이 없는 파일을 확인 후 삭제하는 프로세스를 진행합니다."
if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 소유자와 그룹이 없는 파일을 찾고 설정합니다."

    echo "소유자가 없는 파일 목록:"
    find / -nouser -print
    echo "그룹이 없는 파일 목록:"
    find / -nogroup -print

    echo "위 목록의 파일을 삭제하시겠습니까? (Y/N)"
    read -r file_owner_answer
    file_owner_answer=$(echo "$file_owner_answer" | tr '[:upper:]' '[:lower:]')
    if [ "$file_owner_answer" = "y" ] || [ "$file_owner_answer" = "yes" ]; then
        echo "삭제 작업을 진행합니다."
        find / -nouser -delete
        find / -nogroup -delete
        echo "삭제 작업이 완료되었습니다."
    elif [ "$file_owner_answer" = "n" ] || [ "$file_owner_answer" = "no" ]; then
        echo "삭제 작업을 취소합니다."
    fi
fi

#2-3 /etc/passwd 파일 소유자 및 권한 설정
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

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 패스워드 파일의 소유자와 권한을 확인 후 설정합니다. "
    ls -l /etc/passwd
    if [ "$(stat -c '%U' /etc/passwd)" != "root" ] || [ "$(stat -c '%a' /etc/passwd)" != "644" ]; then
        echo "\"passwd\" 파일 소유자가 root가 아니거나 파일의 권한이 644가 아닙니다."
        echo "소유자를 root로, 권한을 644로 변경합니다. "
        sudo chown root /etc/passwd
        sudo chmod 644 /etc/passwd
        echo "-fix 인자값에 따라 설정을 변경했습니다. "
    else
        echo "소유자가 root이고 파일의 권한이 644입니다. 변경사항이 없습니다."
    fi
fi

#2-5 /etc/hosts 파일 소유자 및 권한 설정
hosts_file_path="/etc/hosts"
host_file_owner=$(stat -c %U "$hosts_file_path")
hosts_file_permissions=$(stat -c %a "$hosts_file_path")

host_required_owner="root"
host_required_permissions="600"

if [ "$hosts_file_owner" = "$host_required_owner" ] && [ "$hosts_file_permissions" -le "$host_required_permissions" ]; then
    echo "양호 : /etc/hosts 파일의 소유자가 root이고, 권한이 600 이하입니다."
else
    echo "취약 : 현재 소유자 : $hosts_file_owner, 현재 권한 : $hosts_file_permissions"
    echo "/etc/hosts 파일 소유자 및 권한 설정 수동 진단 필요 요망. "
fi

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 hosts 파일의 소유자와 권한을 확인합니다."
    ls -l /etc/hosts
    if [ "$(stat -c '%U' /etc/hosts)" != "root" ] || [ "$(stat -c '%a' /etc/hosts)" -gt "600" ]; then
        echo "\"hosts\" 파일 소유자가 root가 아니거나 파일의 권한이 600이하가 아닙니다."
        echo "소유자를 root로, 권한을 600으로 변경합니다. "
        chown root /etc/hosts
        chmod 600 /etc/hosts
        echo "/etc/hosts 파일 소유자 및 권한을 설정했습니다. "
    else
        echo "소유자가 root이고, 파일의 권한이 600입니다. 변경할 필요가 없습니다. "
    fi
fi

#2-6 /etc/(x)inetd.conf 파일 소유자 및 권한
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
    echo "$inetd_conf_file_owner,$inetd_conf_file_permissions 수동 점검 요망"
fi

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 xinetd.conf 파일과 xinetd.d 디렉터리 내의 파일의 소유자와 권한을 확인합니다."
    echo "/etc/xinetd.conf 파일 : "
    ls -l /etc/xinetd.conf
    echo "/etc/xinetd.d 디렉터리 : "
    ls -al /etc/xinetd.d

    if [ "$(stat -c '%U' /etc/xinetd.conf)" != "root" ] || [ "$(stat -c '%a' /etc/xinetd.conf)" != "600" ]; then
        echo "\"xinetd.conf\" 파일 소유자가 root가 아니거나 파일의 권한이 600이 아닙니다."
        echo "소유자를 root로, 권한을 600으로 변경합니다."
        chown root /etc/xinetd.conf
        chmod 600 /etc/xinetd.conf

        echo "설정 변경이 완료되었습니다."
    else
        echo "xinetd.conf 파일이 양호합니다."
    fi

    xinetd_insecure_files=$(find /etc/xinetd.d/ -type f \( ! -user root -o ! -perm -600 \))
    if [ -n "$xinetd_insecure_files" ]; then
        echo "xinetd.d 디렉터리 내의 일부 파일이 취약합니다."
        echo "소유자를 root로, 권한을 600으로 변경합니다."
        chown root /etc/xinetd.d/*
        chmod 600 /etc/xinetd.d/*
        echo "설정 변경이 완료되었습니다."
    else
        echo "xinetd.d 디렉터리 내의 모든 파일이 양호합니다."
    fi
fi

#2-7 /etc/syslog.conf file owner authority setiing 
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
        for acceptable_owner in "${required_syslog_owners[@]}"; do
            if [ "$input_owner" = "$acceptable_owner" ]; then
                return 0
            fi
        done
        return 1
    }
    if is_owner_acceptable "$syslog_conf_file_owner" && [ "$syslog_conf_file_permissions" -le "$required_syslog_permissions" ]; then
        echo "양호 : /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하입니다. "
    else
        echo "취약 : 현재 소유자 : $syslog_conf_file_owner, 현재 권한 : $syslog_conf_file_permissions"
        echo "/etc/syslog.conf 파일 소유자 및 권한 설정 수동 진단 필요 요망 . "
    fi


if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 조치를 시작합니다. "
    ls -l /etc/syslog.conf
    if ! is_owner_acceptable "$syslog_conf_file_owner" || [ "$syslog_conf_file_permissions" -gt "$required_syslog_permissions" ]; then
        echo "\"syslog.conf\" 파일 소유자가 root, bin, sys가 아니거나 파일의 권한이 640이 아닙니다."
        echo "소유자를 root로, 권한을 640으로 변경합니다. "
        chown root /etc/syslog.conf
        chmod 640 /etc/syslog.conf
        echo "/etc/syslog.conf 파일 소유자 및 권한을 설정했습니다. "
    else
        echo "소유자가 root또는 bin, sys이고, 파일의 권한이 640 이하입니다. 변경사항이 없습니다."
    fi

fi

#





