SNMP_CONF="/etc/snmp/snmp.conf"

community_name=$(grep -Po '(?<=com2sec notConfigUser default )\S+' "$SNMP_CONF")

if [[ "$community_name" == "public" || "$community_name" == "private" ]]; then
    echo "취약"
else
    echo "양호"
fi