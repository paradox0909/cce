if [ ! -f /etc/exports ]; then
    echo "/etc/exports 파일이 존재하지 않습니다. NFS 서비스가 설정되지 않았을 수 있습니다."
    exit 1
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
