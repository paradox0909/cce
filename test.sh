#3.5 Dos attack service disabled

dos_xinetd_dir="/etc/xinetd.d/"
dos_service=("echo" "discard" "daytime" "chargen" "ntp" "snmp")

for dos_service in "$(dos_services[@])"
do
    dos_conf_file="$(dos_xinetd_dir)$(dos_service)"

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
    if [ -f $dos_conf_file ]; then
        dos_disabled_status=$(grep -i "disable[[:space:]]*=[[:space:]]*yes" "$dos_conf_file")
        if [ -z "$dos_disable_status" ]; then
            echo "$dos_service disabled"
            dos_all_disabled=false
        fi
    fi
done

if $dos_all_disabled; then
    echo "양호 : 사용하지 않는 Dos 공격에 취약한 서비스가 비활성화됨."
else
    echo "취약 : 사용하지 않는 Dos 공격에 취약한 서비스가 있습니다."
testtest