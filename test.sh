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