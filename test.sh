#!/bin/bash

# SNMP 서비스 상태 확인
if systemctl is-active --quiet snmpd; then
    echo "취약"   # SNMP 서비스가 구동 중인 경우
else
    echo "양호"   # SNMP 서비스가 구동되지 않은 경우
fi
