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

# u-29 3.11