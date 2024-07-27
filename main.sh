#!/bin/bash

# apt update
# echo "apt 저장소를 업데이트 하였습니다."
echo "########################################################################"
echo "#                         CCE Vulnerability Checker                     #"
echo "#                                               Made By : Paradox       #"
echo "########################################################################"
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
        echo "수동 진단 요망: $etc_passwd_user"
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

# 1-5 root 이외의 UID가 '0' 금지
uid_TEMP_FILE="/tmp/passwd.tmp"

while IFS=: read -r uid_username uid_password uid_uid uid_gid uid_info uid_home uid_shell; do
    if [[ "$uid_uid" -eq - && "$uid_username" != "root" ]]; then
        echo "UID가 0인 계정을 찾았습니다."
        echo "UID가 0인 계정명 :$uid_username"
        uid_new_uid=1001
        while grep -q ":$uid_new_uid:" /etc/passwd; do
        ((uid_new_uid++))
        done
        echo "$uid_username 사용자의 UID를 0에서 $uid_new_uid(으)로 변경 중"
        usermod -u "$uid_new_uid" "$uid_username"
    fi
done < /etc/paswd
grep ':0:' /etc/passwd | grep -v '^root:'

if [[ $? -eq 0 ]]; then
  echo "Error: Some users still have UID 0 other than root."
else
  echo "Success: No u-sers other than root have UID 0."
fi

#1-6 root 계정 su 제한
root_su_group_file="/etc/group"
root_su_su_command="/usr/bin/su"
root_su_wheel_group="wheel"
root_su_pam_file="/etc/pam.d/su"
root_su_aix_security_file="/etc/security/user"
root_su_hpux_security_file="/etc/default/security"

check_group_exists() {
    grep -q "^$root_su_wheel_group:" $root_su_group_file
}

check_su_command_permission() {
    local permissions
    permissions=$(ls -l $root_su_su_command | awk '{print $1}')
    [[ "$permissions" == "-rwsr-x---" ]]
}

check_pam_wheel_config() {
    grep -q "auth required .* pam_wheel.so" $root_su_pam_file
}

check_aix_security_setting() {
    grep -q "default.*sgroup=staff" $root_su_aix_security_file
}

check_hpux_security_setting() {
    grep -q "SU_ROOT_GROUP=wheel" $root_su_hpux_security_file
}
##start
echo "그룹 존재 여부 확인 중..."
if check_group_exists; then
    echo "그룹 $root_su_wheel_group 이(가) 존재합니다."
else
    echo "그룹 $root_su_wheel_group 이(가) 존재하지 않습니다."
fi

echo "su 명령어 권한 확인 중..."
if check_su_command_permission; then
    echo "$root_su_su_command 의 권한이 올바르게 설정되어 있습니다."
else
    echo "$root_su_su_command 의 권한이 올바르게 설정되지 않았습니다."
fi

echo "PAM wheel 구성 확인 중..."
if check_pam_wheel_config; then
    echo "PAM wheel 구성이 올바르게 설정되어 있습니다."
else
    echo "PAM wheel 구성이 설정되어 있지 않습니다."
fi

echo "AIX 보안 설정 확인 중..."
if check_aix_security_setting; then
    echo "AIX 보안 설정이 올바르게 설정되어 있습니다."
else
    echo "AIX 보안 설정이 설정되어 있지 않습니다."
fi

echo "HP-UX 보안 설정 확인 중..."
if check_hpux_security_setting; then
    echo "HP-UX 보안 설정이 올바르게 설정되어 있습니다."
else
    echo "HP-UX 보안 설정이 설정되어 있지 않습니다."
fi

# 1-7 패스워드 최소 길이 설정
MAX_PASSLENGTH=$(grep '^PASSLENGTH=' /etc/default/passwd | cut -d '=' -f 2)
if [ "$MAX_PASSLENGTH" -ge 8 ]; then
  echo "양호"
else
  echo "취약"
fi

# 1-8, 1-9 패스워드 최대 사용기간 설정 및 패스워드 최소 사용기간 설정

LOGIN_DEFS_FILE="/etc/login.defs"

current_max_days=$(grep "^PASS_MAX_DAYS" $LOGIN_DEFS_FILE | awk '{print $2}')

current_min_days=$(grep "^PASS_MIN_DAYS" $LOGIN_DEFS_FILE | awk '{print $2}')

if [ "$current_max_days" -le 90 ]; then
    echo "PASS_MAX_DAYS 설정: 양호"
else
    echo "PASS_MAX_DAYS 설정: 취약"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' $LOGIN_DEFS_FILE
    echo "PASS_MAX_DAYS 값을 90으로 변경했습니다."
fi

if [ "$current_min_days" -eq 100 ]; then
    echo "PASS_MIN_DAYS 설정: 양호"
else
    echo "PASS_MIN_DAYS 설정: 취약"
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 100/' $LOGIN_DEFS_FILE
    echo "PASS_MIN_DAYS 값을 100으로 변경했습니다."
fi

# 1-10 불필요한 계정 제거
UNWANTED_ACCOUNTS=("lp" "uucp" "nuucp")

UNWANTED_FOUND=false

for ACCOUNT in "${UNWANTED_ACCOUNTS[@]}"; do
  if grep -q "^${ACCOUNT}:" /etc/passwd; then
    UNWANTED_FOUND=true
    echo "Deleting account: $ACCOUNT"
    sudo userdel $ACCOUNT
  fi
done

if [ "$UNWANTED_FOUND" = false ]; then
  echo "양호"
else
  echo "취약"
fi

#1-11 관리자 그룹에 최소한의 계정 포함
cp /etc/group /etc/group.bak

ROOT_GROUP_LINE=$(grep '^root:' /etc/group)
ROOT_USERS=$(echo $ROOT_GROUP_LINE | cut -d':' -f4)

NECESSARY_USERS="root"

VULNERABLE="no"
for USER in $(echo $ROOT_USERS | tr ',' ' '); do
    if [[ $USER != "root" ]]; then
        VULNERABLE="yes"
        break
    fi
done

if [[ $VULNERABLE == "yes" ]]; then
    echo "취약"
    NEW_ROOT_USERS=$(echo $ROOT_USERS | tr ',' '\n' | grep -v -w -F -e $NECESSARY_USERS | tr '\n' ',' | sed 's/,$//')
    sed -i "/^root:/ s/:$ROOT_USERS/:$NECESSARY_USERS/" /etc/group
else
    echo "양호"
fi

# 1-12 계정이 존재하지 않는 GID 금지
TMP_GROUPS=$(mktemp)
TMP_USERS=$(mktemp)

cat /etc/group | cut -d: -f1,3 | awk -F: '{print $1 " " $2}' > "$TMP_GROUPS"

cat /etc/passwd | cut -d: -f1,3 | awk -F: '{print $2}' > "$TMP_USERS"

status="양호"

while IFS=" " read -r group gid; do
    if ! grep -q "^$gid$" "$TMP_USERS"; then
        echo "GID $gid가 사용자 목록에 존재하지 않음: $group"
        
        groupdel "$group" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "그룹 삭제 성공: $group"
        else
            echo "그룹 삭제 실패: $group"
            status="취약"
        fi
        
        status="취약"
    fi
done < "$TMP_GROUPS"

rm -f "$TMP_GROUPS" "$TMP_USERS"

# 1-13 동일한 UID 금지
TMP_UIDS=$(mktemp)
TMP_DUPLICATES=$(mktemp)

cat /etc/passwd | cut -d: -f3 | sort | uniq -d > "$TMP_DUPLICATES"

if [ ! -s "$TMP_DUPLICATES" ]; then
    echo "양호"
    rm -f "$TMP_UIDS" "$TMP_DUPLICATES"
    exit 0
fi

status="취약"

while read -r uid; do
    echo "중복 UID 발견: $uid"

    while read -r user _ uid2 _; do
        if [ "$uid" = "$uid2" ]; then
            echo "UID $uid을 가진 사용자: $user"

            new_uid=$(awk -F: -v uid="$uid" '$3 >= uid { print $3 }' /etc/passwd | sort -n | tail -1)
            new_uid=$((new_uid + 1))

            echo "사용자 $user의 UID를 $uid에서 $new_uid로 변경합니다."

            usermod -u "$new_uid" "$user"

            find / -user "$uid" -exec chown -h "$user":"$user" {} \;

            groupmod -g "$new_uid" "$user" 2>/dev/null

            echo "UID 변경 완료: $user"
        fi
    done < /etc/passwd

done < "$TMP_DUPLICATES"

rm -f "$TMP_UIDS" "$TMP_DUPLICATES"

echo "$status"

# 1-14 사용자 shell 점검
#!/bin/bash

check_and_update_shells() {
    while IFS=: read -r username password uid gid full_name home_dir shell; do
        if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" ]]; then
            if [[ "$uid" -ge 100 && "$uid" -lt 1000 ]]; then
                echo "$username 계정의 로그인 쉘이 올바르지 않습니다. 수정이 필요합니다."
                sudo usermod -s /sbin/nologin "$username"
                echo "$username 계정의 로그인 쉘을 /sbin/nologin으로 변경하였습니다."
            fi
        else
            echo "$username 계정의 로그인 쉘이 올바릅니다."
        fi
    done < /etc/passwd
}

check_and_update_shells

#1-15 Session Timeout 설정
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

# 2-4 /etc/shadow 파일 소유자 및 권한 설정

shadow_owner=$1(ls -l /etc/shadow | awk '{print $3}')
shadow_permissions=$(stat -c %a /etc/shadow)

if [ "$shadow_owner" = "root" && [ "$shadow_permissions" = -le 400 ]]; then
    echo "양호"
else
    echo "취약"
    chown root /etc/shadow
    chown 400 /etc/shadow

fi
echo "/etc/shadow 점검 및 수정 완료"

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
    syslog_acceptable_owners=$("root" "bin" "sys")
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

#u-12 /etc/services 파일 소유자 및 권한 설정
check_services_file() {
    servi_result="양호"

    if [ ! -e /etc/services ]; then
        echo "취약: /etc/services 파일이 존재하지 않습니다."
        servi_result="취약"
    fi

    servi_OWNER=$(stat -c %U /etc/services)
    if [ "$servi_OWNER" != "root" ] && [ "$servi_OWNER" != "bin" ] && [ "$servi_OWNER" != "sys" ]; then
        echo "취약: /etc/services 파일 소유자가 root, bin, sys 중 하나가 아닙니다."
        servi_result="취약"
    fi

    servi_PERMS=$(stat -c %a /etc/services)
    
    if ! echo "$servi_PERMS" | grep -qE '^[0-7]{3}$'; then
        echo "취약: /etc/services 파일 권한이 올바르지 않습니다."
        servi_result="취약"
    elif [ "$servi_PERMS" -gt 644 ]; then
        echo "취약: /etc/services 파일 권한이 644 이하가 아닙니다."
        servi_result="취약"
    fi

    echo "$servi_result"
}

check_services_file

#2-9 SUID, SGID, Setiing file check
SUID_SGID_SEARCH_DIR="/"

suid_sgid_files=$(find $SUID_SGID_SEARCH_DIR -perm /6000 -type f 2>/dev/null)

CRITICAL_EXECUTABLES=("/bin/su" "/usr/bin/passwd" "/usr/bin/chsh" "/usr/bin/gpasswd" "/usr/bin/sudo" "/sbin/mount" "/sbin/umount")


TARGET_GROUP="trustedgroup"

check_critical_executables() {
    for critical_executable in "${CRITICAL_EXECUTABLES[@]}"; do
        if [ -f "$critical_executable" ]; then
            if [ -u "$critical_executable" ] || [ -g "$critical_executable" ]; then
                echo "취약: 주요 실행파일 $critical_executable 에 SUID/SGID 설정이 있습니다."
            else
                echo "양호: 주요 실행파일 $critical_executable 에 SUID/SGID 설정이 없습니다."
            fi
        else
            echo "주의: 주요 실행파일 $critical_executable 를 찾을 수 없습니다."
        fi
    done
}

fix_suid_sgid() {
    echo "SUID 및 SGID 비트를 제거하거나 특정 그룹으로 제한하는 중..."
    for suid_sgid_file in $suid_sgid_files; do
        echo "수정 중: $suid_sgid_file"
        /usr/bin/chgrp $TARGET_GROUP "$suid_sgid_file"
        /usr/bin/chmod 4750 "$suid_sgid_file"
    done
}

echo "SUID 및 SGID 설정된 파일 목록:"
echo "$suid_sgid_files"
echo

check_critical_executables

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 수정이 진행됩니다."
    fix_suid_sgid
fi

#2-10 User, System Startup file & Environment file owner and authority Settings
env_sys_files=(".profile" ".kshrc" ".cshrc" ".bashrc" ".bash_profile" ".login" ".exrc" ".netrc")
env_sys_home_dir=$HOME
env_sys_user=$(whoami)

env_sys_check_file() {
    env_sys_file_path=$1
    if [ -f "$env_sys_file_path" ]; then
        env_sys_owner=$(stat -c '%U' "$env_sys_file_path")
        env_sys_perms=$(stat -c '%a' "$env_sys_file_path")
        if [ "$env_sys_owner" == "root" ] || [ "$env_sys_owner" == "$env_sys_user" ]; then
            if [ "${env_sys_perms: -1}" -le 2 ] && [ "${env_sys_perms: -2:1}" -le 2 ] && [ "${env_sys_perms: -3:1}" -le 6 ]; then
                echo "$env_sys_file_path: 양호"
            else
                echo "$env_sys_file_path: 취약"
            fi
        else
            echo "$env_sys_file_path: 취약"
        fi
    else
        echo "$env_sys_file_path: 파일이 존재하지 않습니다"
    fi
}

for env_sys_file in "${env_sys_files[@]}"; do
    env_sys_check_file "$env_sys_home_dir/$env_sys_file"
done

#2-11 world writealble file check
world_writable_critical_files=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/crontab"
    "/etc/ssh/sshd_config"
    "/etc/hosts"
    "/etc/resolv.conf"
)

check_world_writable() {
    for world_writable_file in "${world_writable_critical_files[@]}"; do
        if [ -w "$world_writable_file" ]; then
            echo "취약: $world_writable_file 파일이 world writable로 설정되어 있습니다."
        else
            echo "양호: $world_writable_file 파일이 world writable로 설정되어 있지 않습니다."
        fi
    done
}

fix_world_writable() {
    for world_writable_file in "${world_writable_critical_files[@]}"; do
        if [ -w "$world_writable_file" ]; then
            chmod o-w "$world_writable_file"
            echo "수정: $world_writable_file 파일의 world writable 권한이 제거되었습니다."
        fi
    done
}

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 수정이 진행됩니다."
    fix_world_writable
else
    check_world_writable
fi

#2-12 Check device files that do not exist in /dev
check_nonexistent_devices() {
    echo "양호: /dev에 대한 파일 점검 수행 중..."
    for dev_not_exist_file in $(find /dev -type f); do
        if ! [[ -c "$dev_not_exist_file" ]]; then
            echo "취약: $dev_not_exist_file 파일은 /dev에 존재하지 않는 device 파일입니다."
        fi
    done
}

fix_nonexistent_devices() {
    echo "수정: /dev에 존재하지 않는 device 파일 제거 완료"
    for dev_not_exist_file in $(find /dev -type f); do
        if ! [[ -c "$dev_not_exist_file" ]]; then
            echo "제거: $dev_not_exist_file 파일 삭제"
            rm -f "$dev_not_exist_file"
        fi
    done
}

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 설정이 진행됩니다."
    fix_nonexistent_devices
else
    check_nonexistent_devices
fi

#2-13 Do not use $HOME/.rhosts, hosts.equiv
 check_rhosts_hosts_equiv() {
    echo "양호: /etc/hosts.equiv, do_not_use_home/.rhosts 파일 점검 수행 중..."

    if [ -f /etc/hosts.equiv ]; then
        if [ "$(stat -c '%U' /etc/hosts.equiv)" == "root" ] && [ "$(stat -c '%a' /etc/hosts.equiv)" -le 600 ] && ! grep -q "+" /etc/hosts.equiv; then
            echo "양호: /etc/hosts.equiv 파일이 안전하게 설정되어 있습니다."
        else
            echo "취약: /etc/hosts.equiv 파일이 안전하지 않게 설정되어 있습니다."
        fi
    else
        echo "양호: /etc/hosts.equiv 파일이 존재하지 않습니다."
    fi

    if [ -f "$do_not_use_home/.rhosts" ]; then
        if [ "$(stat -c '%U' "$do_not_use_home/.rhosts")" == "$(whoami)" ] && [ "$(stat -c '%a' "$do_not_use_home/.rhosts")" -le 600 ] && ! grep -q "+" "$do_not_use_home/.rhosts"; then
            echo "양호: do_not_use_home/.rhosts 파일이 안전하게 설정되어 있습니다."
        else
            echo "취약: do_not_use_home/.rhosts 파일이 안전하지 않게 설정되어 있습니다."
        fi
    else
        echo "양호: do_not_use_home/.rhosts 파일이 존재하지 않습니다."
    fi
}

fix_rhosts_hosts_equiv() {
    echo "수정: /etc/hosts.equiv, do_not_use_home/.rhosts 파일 설정 수정합니다."

    if [ -f /etc/hosts.equiv ]; then
        chown root /etc/hosts.equiv
        chmod 600 /etc/hosts.equiv
        sed -i 's/+//g' /etc/hosts.equiv
        echo "수정: /etc/hosts.equiv 파일이 안전하게 설정되었습니다."
    fi

    if [ -f "$do_not_use_home/.rhosts" ]; then
        chown "$(whoami)" "$do_not_use_home/.rhosts"
        chmod 600 "$do_not_use_home/.rhosts"
        sed -i 's/+//g' "$do_not_use_home/.rhosts"
        echo "수정: do_not_use_home/.rhosts 파일이 안전하게 설정되었습니다."
    fi
}

if [ "$1" = "-fix" ]; then
    echo "-fix 인자값에 따라 설정이 진행됩니다. "
    fix_rhosts_hosts_equiv
else
    check_rhosts_hosts_equiv
fi

#2-14 Connect Ip and Port

HOST_DENY="/etc/host.deny"
HOSTS_ALLOW="/etc/hosts.allow"

if [[ -e $HOST_DENY  || -e $HOSTS_ALLOW ]]; then
    echo "양호"
else
    echo "수동 진단 필요"
fi

#connection ip and port limit


# 3.1 Finger Service disable 
FINGER_INETD_CONF="/etc/inetd.conf"

if [ -e "$FINGER_INETD_CONF" ]; then
    FINGER_SERVICE=$(grep -i 'finger' $FINGER_INETD_CONF)
    if [ -z "$FINGER_SERVICE" ] || echo "$FINGER_SERVICE" | grep -q '^#'; then
        ehco "양호 : Finger Service Disabled"
    else
        echo "취약 : Finger Service Enabled"
    fi
else
    echo "$FINGER_INETD_CONF 파일이 존재하지 않습니다. "
fi

if [ "$1" = "-fix" ]; then
    if [ -f "$INETD_CONF" ]; then
        sed -i '/^[^#]*finger/s/^/# /' "$INETD_CONF"
        echo "-fix 인자에 따라 $INETD_CONF 파일을 수정했습니다."
        grep -i 'finger' "$INETD_CONF"
    else
        echo "$INETD_CONF 파일이 존재하지 않습니다."
    fi
else
    echo "inetd 서비스를 재시작할 수 없습니다. 수동 진단 요망"
fi

# 3.2 Anonymous FTP 비활성화
cp /etc/passwd /etc/passwd.backup

ftp_accounts=("ftp" "anonymous")
if grep -qE "^(ftp|anonymous):" /etc/passwd; then
    echo "취약"
else
    echo "양호"
fi

if [ "$1" = "-fix" ]; then
    echo "-fix 인자에 따라 수정이 시작됩니다." 
    for account in "${ftp_accounts[@]}"; do
        sed -i "/^${account}:/d" /etc/passwd
    done
    echo "ftp 및 anonymous 계정이 /etc/passwd 파일에서 삭제되었습니다."
fi

#3.3 r 계열 서비스 비활성화
r_service_dir="/etc/xinetd.d"
r_main_services=("rlogin" "rsh" "rexec")

for r_service in "${r_main_services[@]}"; do
    r_service_file="$r_service_dir/$r_service"
    if [[ -f $r_service_file ]]; then
        if grep -q "^disable" "$r_service_file"; then
            sed -i 's/^disable.*/disable = yes/' "$r_service_file"
        else
            echo "disable = yes" >> "$r_service_file"
        fi
        echo "$r_service service has been disabled."
    else
        echo "$r_service service file not found."
    fi
done

#3.4 crond file owner and permissions
crond_check_permissions() {
    crontab_command_path=$(which crontab)
    crontab_command_permissions=$(stat -c "%a" "$crontab_command_path")
    cron_related_files=(
        "/etc/cron.d/*"
        "/etc/cron.hourly/*"
        "/etc/cron.daily/*"
        "/etc/cron.weekly/*"
        "/etc/cron.monthly/*"
        "/var/spool/cron/*"
        "/var/spool/cron/crontabs/*"
        "/etc/cron.d/cron.allow"
        "/etc/cron.d/cron.deny"
    )

    if [[ $crontab_command_permissions -le 750 ]]; then
        for cron_file in "${cron_related_files[@]}"; do
            for file in $cron_file; do
                if [ -e "$file" ]; then
                    cron_file_permissions=$(stat -c "%a" "$file")
                    if [[ $cron_file_permissions -gt 640 ]]; then
                        echo "취약: $file permissions are $cron_file_permissions"
                        return
                    fi
                fi
            done
        done
        echo "양호"
    else
        echo "취약: crontab command permissions are $crontab_command_permissions"
    fi
}

crond_fix_permissions() {
    crontab_command_path=$(which crontab)
    chmod 750 "$crontab_command_path"

    cron_related_files=(
        "/etc/cron.d/*"
        "/etc/cron.hourly/*"
        "/etc/cron.daily/*"
        "/etc/cron.weekly/*"
        "/etc/cron.monthly/*"
        "/var/spool/cron/*"
        "/var/spool/cron/crontabs/*"
        "/etc/cron.d/cron.allow"
        "/etc/cron.d/cron.deny"
    )

    for cron_file in "${cron_related_files[@]}"; do
        for file in $cron_file; do
            if [ -e "$file" ]; then
                chown root "$file"
                chmod 640 "$file"
            fi
        done
    done
}

if [ "$1" = "-fix" ]; then
    echo "-fix 인자에 따라 수정이 진행됩니다."
    crond_fix_permissions
else
    crond_check_permissions
fi


#3.5 Dos attack service disabled
dos_xinetd_dir="/etc/xinetd.d/"
dos_services=("echo" "discard" "daytime" "chargen" "ntp" "snmp")

for dos_service in "${dos_services[@]}"
do
    dos_conf_file="${dos_xinetd_dir}${dos_service}"

    if [ -f "$dos_conf_file" ]; then
        echo "$dos_service"
        sed -i 's/disable[[:space:]]*=[[:space:]]*no/disable = yes/g' "$dos_conf_file"
    else
        echo "$dos_service 구성 파일을 찾을 수 없습니다."
    fi
done

echo "서비스를 재시작합니다"
service xinetd restart
echo "설정 완료"

dos_all_disabled=true
for dos_service in "${dos_services[@]}"
do
    dos_conf_file="${dos_xinetd_dir}${dos_service}"
    if [ -f "$dos_conf_file" ]; then
        dos_disabled_status=$(grep -i "disable[[:space:]]*=[[:space:]]*yes" "$dos_conf_file")
        if [ -z "$dos_disabled_status" ]; then
            echo "$dos_service disabled"
            dos_all_disabled=false
        fi
    fi
done

if $dos_all_disabled; then
    echo "양호 : 사용하지 않는 Dos 공격에 취약한 서비스가 비활성화됨."
else
    echo "취약 : 사용하지 않는 Dos 공격에 취약한 서비스가 있습니다."
fi
echo "Debug: End of script reached"

#u-24 3.6 nfs service disable
nfs_processes=$(ps -ef | grep -E "nfsd|statd|mountd|lockd" | grep -v grep)

if [ -z "$nfs_processes" ]; then
    echo "양호"
else
    echo "취약"
x
    echo "NFS 데몬을 종료합니다."
    sudo systemctl stop nfs-server.service
    sudo systemctl stop nfs-config.service
    sudo systemctl stop rpcbind.service

    echo "NFS 데몬을 설정합니다."
    sudo systemctl disable nfs-server.service
    sudo systemctl disable nfs-config.service
    sudo systemctl disable rpcbind.service                                                                                  ㅋ

    sudo update-rc.d nfs-kernel-server disable
    sudo update-rc.d nfs-common disable
fi

echo "NFS 파일을 제거합니다."
sudo rm /etc/exports

echo "NFS 서비스 비활성화 완료"

#u-25 3.7 NFS access control
if [ ! -f /etc/exports ]; then
    echo "/etc/exports 파일이 존재하지 않습니다. NFS 서비스가 설정되지 않았을 수 있습니다."
fi

if grep -q '^\s*/.* *(rw|ro|)' /etc/exports; then
    echo "취약: /etc/exports 파일에 everyone 공유가 설정되어 있습니다."
else
    echo "양호: /etc/exports 파일에 everyone 공유가 설정되어 있지 않습니다."
fi

if systemctl is-active --quiet nfs-server; then
    echo "NFS 서비스가 실행 중입니다."
    
    echo "현재 /etc/exports 파일의 내용을 점검합니다:"
    cat /etc/exports

    echo "추가할 디렉토리와 호스트명을 입력하십시오 (예: /stand host1 host2 또는 /stand 192.168.1.1):"
    read new_export

    echo "$new_export" >> /etc/exports

    echo "/etc/exports 파일에 새로운 설정이 추가되었습니다:"
    cat /etc/exports

    echo "NFS 서비스를 다시 시작합니다."
    systemctl restart nfs-server

    echo "NFS 서비스가 재시작되었습니다."
else
    echo "NFS 서비스가 실행 중이지 않습니다. 불필요한 NFS 서비스를 사용하지 않으므로 양호합니다."
fi

#u-26 3.8 delete automountd
automount_SERVICE_STATUS=$(ps aux | grep automountd | grep -v grep)

if [ -z "$automount_SERVICE_STATUS" ]; then
    echo "양호"
else
    echo "취약"
 
    if [ "$1" = "-fix" ]; then
        echo "-fix 인자에 따라 수정이 진행됩니다."
        automount_PID=$(echo "$automount_SERVICE_STATUS" | awk '{print $2}')
        kill -9 $automount_PID

        automount_INIT_SCRIPTS=$(ls -al /etc/rc.d/rc*.d/* | grep automountd)
        for automount_SCRIPT in $automount_INIT_SCRIPTS; do
            mv $automount_SCRIPT $(dirname $automount_SCRIPT)/_$(basename $automount_SCRIPT)
        done
    fi
fi

# u-27 3.9 Check RPC service
rpc_RPC_SERVICES=("rpc.cmsd")
rpc_INETD_CONF="/etc/inetd.conf"

rpc_check_and_disable_rpc_services() {
    local rpc_service
    local rpc_is_vulnerable=false

    for rpc_service in "${rpc_RPC_SERVICES[@]}"; do
        if grep -E "^$rpc_service" "$rpc_INETD_CONF" > /dev/null; then
            echo "취약: $rpc_service 서비스가 활성화 되어 있습니다."
            rpc_is_vulnerable=true
            sed -i.bak -e "s|^$rpc_service|#$rpc_service|" "$rpc_INETD_CONF"
        fi
    done

    if [ "$rpc_is_vulnerable" = true ]; then
        echo "취약: 불필요한 RPC 서비스가 활성화 되어 있습니다. 서비스를 비활성화합니다."
        rpc_restart_inetd
    else
        echo "양호: 불필요한 RPC 서비스가 비활성화 되어 있습니다."
    fi
}
rpc_restart_inetd() {

    rpc_INETD_PID=$(pgrep inetd)
    
    if [ -n "$rpc_INETD_PID" ]; then
        echo "inetd 서비스 재시작 중... (PID: $rpc_INETD_PID)"
        kill -HUP "$rpc_INETD_PID"
        echo "inetd 서비스가 재시작되었습니다."
    else
        echo "inetd 서비스가 실행 중이지 않습니다."
    fi
}

rpc_check_and_disable_rpc_services

# u-28 3.10 NIS, NIS+ Check

NIS_SERVICES=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")
NIS_SCRIPT_PATH="/etc/rc.d/rc*.d/"
NIS_SERVICE_CHECK_CMD="ps -ef | egrep 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated'"

NIS_check_and_disable_services() {
    local NIS_service
    local NIS_is_vulnerable=false

    for NIS_service in "${NIS_SERVICES[@]}"; do
        if eval "$NIS_SERVICE_CHECK_CMD" | grep "$NIS_service" > /dev/null; then
            echo "취약: $NIS_service 서비스가 활성화 되어 있습니다."
            NIS_is_vulnerable=true
            NIS_disable_service "$NIS_service"
        fi
    done

    if [ "$NIS_is_vulnerable" = true ]; then
        echo "취약: 불필요한 NIS 서비스가 활성화 되어 있습니다. 서비스를 비활성화합니다."
    else
        echo "양호: 불필요한 NIS 서비스가 비활성화 되어 있습니다."
    fi
}

NIS_disable_service() {
    local NIS_service=$1
    local NIS_service_pid

    NIS_service_pid=$(pgrep "$NIS_service")
    if [ -n "$NIS_service_pid" ]; then
        kill -9 "$NIS_service_pid"
        echo "$NIS_service 서비스를 종료했습니다. (PID: $NIS_service_pid)"
    fi

    for script in $(ls -1 "$NIS_SCRIPT_PATH" | grep "$NIS_service"); do
        mv "$script" "${script}.bak"
        echo "$script 파일명을 ${script}.bak로 변경했습니다."
    done
}
NIS_check_and_disable_services


# u-29 3.11 tftp, talk service disable
tftp_talk_SERVICES=("tftp" "talk" "ntalk")
tftp_talk_INETD_CONF="/etc/inetd.conf"
tftp_talk_XINETD_DIR="/etc/xinetd.d"

tftp_talk_check_and_disable_services() {
    local tftp_talk_service
    local tftp_talk_is_vulnerable=false

    for tftp_talk_service in "${tftp_talk_SERVICES[@]}"; do
        if grep -E "^$tftp_talk_service" "$tftp_talk_INETD_CONF" > /dev/null 2>&1; then
            echo "취약: $tftp_talk_service 서비스가 inetd.conf에서 활성화 되어 있습니다."
            tftp_talk_is_vulnerable=true
            sed -i.bak -e "s|^$tftp_talk_service|#$tftp_talk_service|" "$tftp_talk_INETD_CONF"
        fi
        if [ -f "$tftp_talk_XINETD_DIR/$tftp_talk_service" ]; then
            if grep -E "disable\s*=\s*no" "$tftp_talk_XINETD_DIR/$tftp_talk_service" > /dev/null 2>&1; then
                echo "취약: $tftp_talk_service 서비스가 xinetd에서 활성화 되어 있습니다."
                tftp_talk_is_vulnerable=true
                sed -i.bak -e "s|disable\s*=\s*no|disable = yes|" "$tftp_talk_XINETD_DIR/$tftp_talk_service"
            fi
        fi
    done

    if [ "$tftp_talk_is_vulnerable" = true ]; then
        echo "취약: 불필요한 서비스가 활성화 되어 있습니다. 서비스를 비활성화합니다."
        tftp_talk_restart_inetd
    else
        echo "양호: 불필요한 서비스가 비활성화 되어 있습니다."
    fi
}

tftp_talk_restart_inetd() {
    if pgrep inetd > /dev/null 2>&1; then
        echo "inetd 서비스를 재시작합니다."
        pkill -HUP inetd
        echo "inetd 서비스가 재시작되었습니다."
    fi
    if pgrep xinetd > /dev/null 2>&1; then
        echo "xinetd 서비스를 재시작합니다."
        pkill -HUP xinetd
        echo "xinetd 서비스가 재시작되었습니다."
    fi
}

tftp_talk_check_and_disable_services

# u-30 3.12 Sendmail Version Check
check_sendmail_running() {
    if ps -ef | grep -v grep | grep sendmail > /dev/null
    then
        echo "Sendmail이 실행 중입니다."
        return 0
    else
        echo "Sendmail이 실행 중이지 않습니다."
        return 1
    fi
}

get_sendmail_version() {
    sendmail -d0.1 -bv root | grep -i version
}

update_sendmail() {
    echo "Sendmail을 업데이트 중..."
    apt update
    apt install sendmail -y
    apt update sendmail -y
}

sendmail_main() {
    echo "Sendmail 서비스 확인 중..."
    if check_sendmail_running
    then
        echo "Sendmail 버전 확인 중..."
        sendmail_version=$(get_sendmail_version)
        echo "현재 Sendmail 버전: $sendmail_version"
        
        sendmail_latest_version="8.15.2"
        
        if [[ $sendmail_version == *"$sendmail_latest_version"* ]]
        then
            echo "Sendmail이 최신 버전입니다."
        else
            echo "Sendmail이 최신 버전이 아닙니다."
            update_sendmail
            apply_sendmail_patches
        fi
    else
        echo "Sendmail 서비스가 실행 중이지 않습니다. 조치가 필요 없습니다."
    fi
}
sendmail_main

# u-31 3.13 Spam Email relay limit
check_sendmail_relay() {
  echo "SMTP 릴레이 제한 설정 확인 중..."
  if ps -ef | grep -v grep | grep sendmail > /dev/null; then
    echo "Sendmail 서비스가 실행 중입니다."

    if grep -q "R$\*" /etc/mail/sendmail.cf && grep -q "550 Relaying denied" /etc/mail/sendmail.cf; then
      echo "SMTP 릴레이 제한이 설정되어 있습니다."
    else
      echo "SMTP 릴레이 제한이 설정되어 있지 않습니다. 보안 설정이 필요합니다."
    fi
  else
    echo "Sendmail 서비스가 실행 중이지 않습니다."
  fi
}

check_sendmail_relay

# u-32 3.14 Normal User Sendmail prevent execution
SENDMAIL_CF="/etc/mail/sendmail.cf"
SENDMAIL_STATUS=$(systemctl is-active sendmail)
cp $SENDMAIL_CF $SENDMAIL_CF.bak

add_restrictqrun_option() {
    if grep -q "O PrivacyOptions=.*restrictqrun" $SENDMAIL_CF; then
        echo "restrictqrun 옵션이 이미 설정되어 있습니다."
    else
        sed -i '/O PrivacyOptions=/ s/$/, restrictqrun/' $SENDMAIL_CF
        echo "restrictqrun 옵션이 추가되었습니다."
    fi
}


if [[ "$SENDMAIL_STATUS" == "inactive" ]]; then
    echo "SMTP 서비스가 사용되지 않습니다. -> 양호"
else
    if grep -q "O PrivacyOptions=.*restrictqrun" $SENDMAIL_CF; then
        echo "일반 사용자의 Sendmail 실행 방지가 설정되어 있습니다. -> 양호"
    else
        echo "SMTP 서비스 사용 중이며, 일반 사용자의 Sendmail 실행 방지가 설정되어 있지 않습니다. -> 취약"
        add_restrictqrun_option
        systemctl restart sendmail
        if [[ $? -eq 0 ]]; then
            echo "Sendmail 서비스가 성공적으로 재시작되었습니다."
        else
            echo "Sendmail 서비스 재시작에 실패하였습니다."
        fi
    fi
fi

# u-33 3.15 DNS Security Version Patch
echo "u-33 DNS 보안 버전 패치는 수동 점검이 필요합니다. "
dns_services=("named" "dnsmasq" "systemd-resolved")
dns_active=false

for service in "${dns_services[@]}"
do
    status=$(systemctl is-active $service)
    if [ "$status" == "active" ]; then
        dns_active=true
        echo "DNS 서비스 사용 중: $service"
    fi
done

if [ "$dns_active" == false ]; then
    echo "DNS 서비스가 사용되지 않습니다."
fi

# u-34 3.16 DNS Zone Transfer Settings
dns_version_DNS_PROCESS=$(ps -ef | grep named | grep -v "grep")

if [ -z "$dns_version_DNS_PROCESS" ]; then
    echo "양호"
fi
dns_version_ALLOW_TRANSFER=$(cat /etc/named.conf 2>/dev/null | grep 'allow-transfer')
dns_version_XFRNETS=$(cat /etc/named.boot 2>/dev/null | grep 'xfrnets')

if [ -n "$dns_version_ALLOW_TRANSFER" ] || [ -n "$dns_version_XFRNETS" ]; then
    if echo "$dns_version_ALLOW_TRANSFER" | grep -q -E '(\{|;|")' && [ -z "$(echo "$dns_version_ALLOW_TRANSFER" | grep 'any')" ]; then
        echo "양호"
    elif echo "$dns_version_XFRNETS" | grep -q -E '(\{|;|")' && [ -z "$(echo "$dns_version_XFRNETS" | grep 'any')" ]; then
        echo "양호"
    else
        echo "취약"
    fi
else
    echo "취약"
fi

# u-35 3.17 webservice directory delete listing
web_dir_APACHE_HOME="/[Apache_home]"
web_dir_HTTPD_CONF="${web_dir_APACHE_HOME}/conf/httpd.conf"
web_dir_INDEXES_OPTIONS=$(grep -E '^ *Options .*Indexes' "${web_dir_HTTPD_CONF}")

if [ -z "${web_dir_INDEXES_OPTIONS}" ]; then
    echo "양호: 디렉터리 리스팅이 제거되어 있습니다."
else
    echo "취약: 디렉터리 리스팅이 활성화되어 있습니다."
fi
sed -i 's/^\( *Options .*\)Indexes\(.*\)/\1\2/g' "${web_dir_HTTPD_CONF}"
systemctl restart apache2  

# u-36 3.18 Webservice web process Permission restrictions
process_permission_httpd_conf="/[Apache_home]/conf/httpd.conf"
process_permission_apache_user=$(grep -E '^User ' $process_permission_httpd_conf | awk '{print $2}')

if [ "$process_permission_apache_user" == "root" ]; then
    echo "취약"
    echo "root 이름을 적절한 사용자 값으로 변경해야 합니다. "
else
    echo "양호"
fi
 
# u-37 3.19 Webservice parent directory Forbidden
#!/bin/bash

# 웹 서버의 홈 디렉토리 경로 설정
par_dir_APACHE_HOME="/path/to/apache"

# 검사할 디렉토리 목록 설정
par_dir_DIRECTORIES=(
  "/path/to/web/directory1"
  "/path/to/web/directory2"
  "/path/to/web/directory3"
)

echo "검사 시작..."

for par_dir_dir in "${par_dir_DIRECTORIES[@]}"
do
  par_dir_allow_override=$(grep -i "^<Directory \"$par_dir_dir\">" $par_dir_APACHE_HOME/conf/httpd.conf -A 5 | grep "AllowOverride")

  if [[ -z "$par_dir_allow_override" ]]; then
    echo "에러: $par_dir_dir 디렉토리의 AllowOverride 설정을 찾을 수 없습니다."
    continue
  fi

  if [[ "$par_dir_allow_override" == *AuthConfig* || "$par_dir_allow_override" == *All* ]]; then
    echo "$par_dir_dir: 양호 - 상위 디렉터리 접근 제한이 설정되어 있습니다."
  else
    echo "$par_dir_dir: 취약 - 상위 디렉터리 접근 제한이 설정되어 있지 않습니다."
  fi
done
echo "검사 완료."

# u-38 3.20 Webservice Delete Remove unnecessary files
web_remove_file_APACHE_HOME="/usr/local/apache"

web_remove_file_UNNECESSARY_FILES=(
    "${web_remove_file_APACHE_HOME}/htdocs/manual"
    "${web_remove_file_APACHE_HOME}/manual"
)
echo "Apache 설치 시 생성된 불필요한 파일 및 디렉터리 제거 스크립트를 시작합니다."

web_remove_file_remove_unnecessary_files() {
    local path="$1"
    if [ -d "$path" ]; then
        rm -rf "$path"
        echo "제거: $path"
    else
        echo "경고: $path 가 존재하지 않습니다."
    fi
}

for web_remove_file_file_or_dir in "${web_remove_file_UNNECESSARY_FILES[@]}"; do
    web_remove_file_remove_unnecessary_files "$web_remove_file_file_or_dir"
done

echo "불필요한 파일 및 디렉터리 제거 완료"

web_remove_file_remaining_files=0
for web_remove_file_file_or_dir in "${web_remove_file_UNNECESSARY_FILES[@]}"; do
    if [ -e "$web_remove_file_file_or_dir" ]; then
        web_remove_file_remaining_files=$((web_remove_file_remaining_files + 1))
    fi
done

if [ "$web_remove_file_remaining_files" -gt 0 ]; then
    echo "취약: 불필요한 파일 또는 디렉터리가 남아 있습니다."
else
    echo "양호: 불필요한 파일 및 디렉터리가 모두 제거되었습니다."
fi

# u-39 3.21 No Webservice Link
no_link_apache_conf="/Apache_home/conf/httpd.conf"

check_follow_symlinks() {
    local result=$(grep -E "<Directory\s+" $no_link_apache_conf | while read -r line; do
        if [[ $line =~ \<Directory ]]; then
            no_link_dir=$(echo $line | sed -r 's/.*<Directory\s+(\S+).*/\1/')
        elif [[ $line =~ Options ]]; then
            if [[ $line =~ FollowSymLinks ]]; then
                echo "양호"
            fi
        fi
    done)
    
    echo "취약"
}

check_follow_symlinks

# u-40 3.22 Limit Webserver File upload and download
up_down_load_HTTPD_CONF="/etc/httpd/conf/httpd.conf"
up_down_load_FILE_SIZE_LIMIT="5242880"

up_down_load_update_limit_request_body() {
    local up_down_load_limit_directive="LimitRequestBody"

    sed -i.bak -E "/<Directory\s+\S+>/,/<\/Directory>/ {
        /$up_down_load_limit_directive/ {
            s/^\s*#*\s*($up_down_load_limit_directive\s+)[0-9]+.*$/\1$up_down_load_FILE_SIZE_LIMIT/
        }
        /^(\s*#*\s*)($up_down_load_limit_directive\s+)?[0-9]+/! {
            /^\s*<\/Directory>/ i \
            LimitRequestBody $up_down_load_FILE_SIZE_LIMIT
        }
    }" "$up_down_load_HTTPD_CONF"

    systemctl reload httpd
}

up_down_load_update_limit_request_body

# u-41 3.23 Separation of web service areas
separation_HTTPD_CONF="/lApache_homelcont/httpd.conf"

separation_DOCUMENT_ROOTS=(
    "/usr/local/apache/htdocs"
    "/usr/local/apache2/htdocs"
    "/var/www/html"
)
grep -Ei "\bDocumentRoot\b" "$separation_HTTPD_CONF" | while read -r separation_line; do
    separation_matched=0
    for separation_root in "${separation_DOCUMENT_ROOTS[@]}"; do
        if [[ "$separation_line" == *"$separation_root"* ]]; then
            separation_matched=1
            break
        fi
    done

    if [ $separation_matched -eq 0 ]; then
        echo "취약: DocumentRoot를 기본 디렉터리로 지정한 경우가 발견되었습니다."
        echo "해당 설정: $separation_line"
        echo
    fi
done
echo "모든 프로세스가 종료되었습니다." 

# u-60 ssh connection allow
ssh_ssh_check=$(ps aux | grep -v grep | grep sshd)

ssh_telnet_check=$(ps aux | grep -v grep | grep telnetd)

if [ -n "$ssh_ssh_check" ]; then
    if [ -z "$ssh_telnet_check" ]; then
        echo "양호"
    else
        echo "Telnet이 설치되어 있어 취약합니다."
    fi
else
    echo "취약: SSH 프로토콜을 사용하지 않습니다."
fi

# u-61 ftp service check
if ps -ef | grep -q '[v]sftpd'; then
    echo "FTP 서비스를 중지합니다..."
    service vsftpd stop
else
    echo "FTP 서비스가 이미 중지되어 있습니다."
fi

# u-62 ftp account shell limit
read -p "FTP 계정 이름을 입력하세요: " ftp_shell_user

if [ -z "$ftp_shell_user" ]; then
    echo "FTP 계정 이름을 입력해야 합니다."
fi

ftp_shell_user_info=$(grep "^$ftp_shell_user:" /etc/passwd)

if [ -z "$ftp_shell_user_info" ]; then
    echo "FTP 계정 '$ftp_shell_user'이(가) 존재하지 않습니다."
fi

ftp_shell=$(echo "$ftp_shell_user_info" | cut -d: -f7)

if [ "$ftp_shell" = "/bin/false" ]; then
    echo "양호: FTP 계정 '$ftp_shell_user'은(는) 제한된 쉘 '/bin/false'을 사용 중입니다."
else
    echo "취약: FTP 계정 '$ftp_shell_user'은(는) 제한된 쉘 '/bin/false'을 사용하지 않고 있습니다."
fi

# u-63 ftp file owner and permission settigs
ftp_file_path="/etc/ftpusers"

ftp_file_owner=$(stat -c "%U" "$ftp_file_path")
if [ "$ftp_file_owner" = "root" ]; then
    ftp_file_permissions=$(stat -c "%a" "$ftp_file_path")
    if [ "$ftp_file_permissions" -le 640 ]; then
        echo "양호: ftpusers 파일의 소유자가 root이고, 권한이 640 이하입니다."
    else
        echo "취약: ftpusers 파일의 권한이 640 이하가 아닙니다."
    fi
else
    echo "취약: ftpusers 파일의 소유자가 root가 아닙니다."
fi

# u-64 ftpusers file settings
ftp_file_service=$(systemctl is-active vsftpd)
if [ "$ftp_file_service" != "active" ]; then
    echo "양호 - FTP 서비스가 비활성화 되어 있습니다."
fi

ftp_file_vsftpd_conf="/etc/vsftpd.conf"
if ! grep -q "^userlist_deny=NO" "$ftp_file_vsftpd_conf"; then
    echo "양호 - vsftpd.conf 파일에서 root 계정 접속을 허용하지 않도록 설정되어 있습니다."
else
    echo "취약 - vsftpd.conf 파일에서 root 계정 접속을 허용하고 있습니다."
fi

# u-65 at 파일 소유자 및 권한 설정
at_allow_file="/etc/at.allow"
at_deny_file="/etc/at.deny"

if [[ ! -f $at_allow_file || ! -f $at_deny_file ]]; then
    echo "Error: at.allow or at.deny file not found."
fi

at_allow_owner=$(stat -c "%U" $at_allow_file)
at_deny_owner=$(stat -c "%U" $at_deny_file)
at_allow_perms=$(stat -c "%a" $at_allow_file)
at_deny_perms=$(stat -c "%a" $at_deny_file)

if [[ $at_allow_owner != "root" || $at_deny_owner != "root" ]]; then
    echo "관리자(root)만이 at.allow 및 at.deny 파일을 제어할 수 있어야 합니다."

fi

if [[ $at_allow_perms -le 640 && $at_deny_perms -le 640 ]]; then
    echo "양호: at.allow 및 at.deny 파일 권한이 640 이하입니다."
else
    echo "취약: at.allow 또는 at.deny 파일의 권한이 640을 초과하거나, 이 파일들이 일반 사용자에게 쓰기 권한이 있습니다."
fi

if grep -q "^at$" /etc/shells && ! grep -q "^at$" /etc/securetty; then
    echo "취약: at 명령어가 일반 사용자에게 허용되어 있습니다."
else
    echo "양호: at 명령어가 일반 사용자에게 제한되어 있습니다."
fi

# u-66 SNMP service test
if systemctl is-active --quiet snmpd; then
    echo "취약" 
else
    echo "양호" 
fi

# u-67 SNMP service community string setiing
SNMP_CONF="/etc/snmp/snmp.conf"

community_name=$(grep -Po '(?<=com2sec notConfigUser default )\S+' "$SNMP_CONF")

if [[ "$community_name" == "public" || "$community_name" == "private" ]]; then
    echo "취약"
else
    echo "양호"
fi

# u-68 warning alert if u log on
logon_check_login_message() {
    logon_service=$1
    logon_config_file=$2
    
    if grep -q "login.warning" $logon_config_file; then
        echo "$logon_service 서비스에 로그온 메시지가 설정되어 있습니다."
        return 0
    else
        echo "$logon_service 서비스에 로그온 메시지가 설정되어 있지 않습니다."
        return 1 
    fi
}


echo "서버 및 Telnet, FTP, SMTP, DNS 서비스의 로그온 메시지 설정 여부를 확인합니다."

logon_telnet_config_file="/etc/inetd.conf"
logon_check_login_message "Telnet" $logon_telnet_config_file
logon_telnet_result=$?

logon_ftp_config_file="/etc/inetd.conf"
logon_check_login_message "FTP" $logon_ftp_config_file
logon_ftp_result=$?

logon_smtp_config_file="/etc/sendmail.cf"  # Assuming Sendmail is used for SMTP
logon_check_login_message "SMTP" $logon_smtp_config_file
logon_smtp_result=$?

logon_dns_config_file="/etc/named.conf"
logon_check_login_message "DNS" $logon_dns_config_file
logon_dns_result=$?

if [ $logon_telnet_result -eq 0 ] && [ $logon_ftp_result -eq 0 ] && [ $logon_smtp_result -eq 0 ] && [ $logon_dns_result -eq 0 ]; then
    echo "양호: 모든 서비스에 로그온 메시지가 설정되어 있습니다."
else
    echo "취약: 다음 서비스 중 로그온 메시지가 설정되지 않았습니다."
    [ $logon_telnet_result -ne 0 ] && echo "- Telnet"
    [ $logon_ftp_result -ne 0 ] && echo "- FTP"
    [ $logon_smtp_result -ne 0 ] && echo "- SMTP"
    [ $logon_dns_result -ne 0 ] && echo "- DNS"

    echo "조치 방법: 각 서비스의 설정 파일($logon_telnet_config_file, $logon_ftp_config_file, $logon_smtp_config_file, $logon_dns_config_file)에서 login.warning 설정을 추가하고, inetd 데몬을 재시작합니다."
fi

# u-69 NFS Setting file access permissions
nfs_set_file="/etc/exports"
nfs_set_owner=$(stat -c '%U' $nfs_set_file)

nfs_set_permissions=$(stat -c '%a' $nfs_set_file | cut -c 2-4)

if [ "$nfs_set_owner" = "root" ] && [ "$nfs_set_permissions" -le 644 ]; then
    echo "양호"
else
    echo "취약"
fi

# u-70 expn, vrfy 명령어 제한
#!/bin/bash
################
if [ ! -f /etc/mail/sendmail.cf ]; then
    echo "sendmail.cf 파일을 찾을 수 없습니다. 취약 상태로 간주합니다."
fi

privacy_options=$(grep ^O PrivacyOptions /etc/mail/sendmail.cf | awk '{print $3}')

if [[ $privacy_options == *noexpn* && $privacy_options == *novrfy* ]]; then
    echo "양호: SMTP 서비스가 미사용이거나 noexpn, novrfy 옵션이 설정되어 있습니다."
else
    echo "취약: SMTP 서비스가 사용 중이거나 noexpn, novrfy 옵션이 설정되어 있지 않습니다."
fi
# u-71 apache webservice information hide
hide_APACHE_CONF="/etc/apache2/apache2.conf"

hide_server_tokens=$(grep -i "^ServerTokens" $hide_APACHE_CONF | awk '{print $2}')
hide_server_signature=$(grep -i "^ServerSignature" $hide_APACHE_CONF | awk '{print $2}')

if [[ "$hide_server_tokens" == "Prod" && "$hide_server_signature" == "Off" ]]; then
    echo "양호: ServerTokens이 Prod로, ServerSignature가 Off로 설정되어 있습니다."
else
    echo "취약: ServerTokens이 Prod로, ServerSignature가 Off로 설정되어 있지 않습니다."
fi

# u-42
echo "최신 보안패치 및 벤더 권고사항 적용은 수동 진단을 요망합니다."
# u-43
echo "로그의 정기적 검토 및 보고는 수동 진단을 요망합니다."
# u-72 log setting
log_set_log_file="/var/log/messages"

check_log_file() {
    local file="$log_set_log_file"

    if [ -f "$file" ]; then
        echo "양호: 로그 파일이 존재합니다."
    else
        echo "취약: 로그 파일이 존재하지 않습니다."
    fi
}

check_log_file


exit 1

#test code
