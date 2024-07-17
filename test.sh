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