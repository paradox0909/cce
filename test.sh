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