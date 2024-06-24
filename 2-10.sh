#!/bin/bash

set -e  # 에러 발생 시 스크립트 중단

# 환경변수 파일 목록
ENVIRONMENT_FILES=".profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc"

# 사용자 홈 디렉토리에서 환경변수 파일들을 찾음
found_files=()

# "/" 디렉토리에서 환경변수 파일들을 찾음
for file_pattern in $ENVIRONMENT_FILES; do
    files_found=$(find / -maxdepth 3 -name "$file_pattern" 2>/dev/null || true)

    # 찾은 파일들을 배열에 추가
    for file_found in $files_found; do
        found_files+=("$file_found")
    done
done

# 함수 정의: 파일 소유자 및 권한 체크 및 수정
check_and_fix_file_permissions() {
    local environment_file="$1"
    local environment_expected_owner="$2"
    local environment_result=""

    # 파일이 존재하는지 확인
    if [ -f "$environment_file" ]; then
        # 소유자 확인
        environment_file_owner=$(stat -c "%U" "$environment_file")
        if [ "$environment_file_owner" = "$environment_expected_owner" ]; then
            # 권한 확인 (소유자와 그룹만 쓰기 권한이 있는지)
            permissions=$(stat -c "%a" "$environment_file")
            if [ "${permissions:5:1}" != "-" ]; then
                environment_result="취약"

                # 수정 옵션이 켜져 있으면 수정
                if [ "$FIX_MODE" = true ]; then
                    echo "환경변수 파일 '$environment_file'의 권한을 수정합니다."
                    chmod o-w "$environment_file"
                    echo "수정 완료."
                    environment_result=$(check_and_fix_file_permissions "$environment_file" "$environment_expected_owner")
                fi
            else
                environment_result="양호"
            fi
        else
            environment_result="취약"

            # 수정 옵션이 켜져 있으면 수정
            if [ "$FIX_MODE" = true ]; then
                echo "환경변수 파일 '$environment_file'의 소유자를 수정합니다."
                chown "$environment_expected_owner" "$environment_file"
                echo "수정 완료."

                # 권한도 함께 수정
                echo "환경변수 파일 '$environment_file'의 권한을 수정합니다."
                chmod o-w "$environment_file"
                echo "수정 완료."
                environment_result=$(check_and_fix_file_permissions "$environment_file" "$environment_expected_owner")
            fi
        fi
    else
        environment_result="취약"
    fi

    echo "$environment_result"
}

# 메인 스크립트 시작

# 옵션 처리
if [ "$1" = "-fix" ]; then
    FIX_MODE=true
else
    FIX_MODE=false
fi

# 찾은 각 환경변수 파일에 대해 체크
for environment_file in "${found_files[@]}"; do
    echo "환경변수 파일: $environment_file"
    environment_result=$(check_and_fix_file_permissions "$environment_file" "$USER")

    if [ "$environment_result" = "양호" ]; then
        echo "상태: 양호"
    else
        echo "상태: 취약"
        if [ "$FIX_MODE" = true ]; then
            echo "수정 방법:"
            echo "# chown $USER \"$environment_file\""
            echo "# chmod o-w \"$environment_file\""
        fi
    fi

    echo
done
