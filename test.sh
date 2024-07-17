
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
