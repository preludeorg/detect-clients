#!/usr/bin/env bash
# Defaults
PRELUDE_API="https://detect.prelude.org"
PRELUDE_ACCOUNT_ID=""
PRELUDE_ACCOUNT_SECRET=""
PROBE_NAME="moonlight"
ENDPOINT_TOKEN=""
DOS="$(uname | awk '{print tolower($0)}')-$(uname -m)"

function usage {
    echo
    echo "Usage: $(basename $0) [-h] -n PROBE_NAME" 2>&1
    echo
    echo '  -h                 Shows Usage'
    echo "  -n PROBE_NAME      Probe Name; Default: ${PROBE_NAME}"
    echo
    exit
}
optstring="n:h"
while getopts ${optstring} arg; do
    case ${arg} in
        n)
            PROBE_NAME="${OPTARG}"
            ;;
        h)
            usage
            ;;
        ?)
            echo "Invalid option: -${OPTARG}."
            echo
            usage
            ;;
    esac
done

register_new_endpoint() {
    echo "[+] Provisioning Detect Endpoint Token..."
    local _token_url="${PRELUDE_API}/account/endpoint"
    ENDPOINT_TOKEN=$(curl -s -X POST -H "account:${PRELUDE_ACCOUNT_ID}" -H "token:${PRELUDE_ACCOUNT_SECRET}" -H "Content-Type: application/json" -d "{\"id\":\"${HOST}\",\"tag\":\"darwin\"}"  "${_token_url}")
    export ENDPOINT_TOKEN
}

download_probe () {
    local _tmp_dir=$1
    local _probe_url="${PRELUDE_API}/download/${PROBE_NAME}?dos=${DOS}"

    echo "[+] Downloading Probe..."
    curl -s -X GET -L -H "token:${ENDPOINT_TOKEN}" "${_probe_url}" > "${_tmp_dir}/${PROBE_NAME}"

    test -r "${_tmp_dir}/${PROBE_NAME}" || {
        echo "[!] Detect failed to download!" >&2
        exit 1
    }
}

install_darwin_plist () {
    local _plist_file_path=$1
    echo "[+] Generate PLIST"

    [[ ! -d "$(dirname $_plist_file_path)" ]] && mkdir "$(dirname $_plist_file_path)"

    cat << EOF | tee "${_plist_file_path}" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>Prelude Detect</string>
        <key>UserName</key>
        <string>${running_user}</string>
        <key>EnvironmentVariables</key>
        <dict>
            <key>PRELUDE_TOKEN</key>
            <string>${ENDPOINT_TOKEN}</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
            <string>${app_dir}/${PROBE_NAME}</string>
        </array>
        <key>KeepAlive</key>
        <true/>
        <key>RunAtLoad</key>
        <true/>
        <key>StartInterval</key>
        <integer>30</integer>
    </dict>
</plist>
EOF
    launchctl unload -w "${_plist_file_path}" 2>/dev/null
    launchctl load -w "${_plist_file_path}"
}

install_darwin() {
  local _running_user="${USER}"
  local _plist_path="/Users/${running_user}/Library/Launchprobes/com.preludesecurity.detect.plist"
  local _app_dir="/Users/${running_user}/.prelude/bin"
  local _app_tmp="/tmp/prelude"
  _primary_group=$(id -gn)

  mkdir -p "${_app_tmp}"
  echo "[*] Standing up as user: ${_running_user}"
  install -o "${_running_user}" -g "${_primary_group}" -m 750 -d "${_app_dir}"
  register_new_endpoint
  download_probe "$_app_tmp"
  install -o "${_running_user}" -g "${_primary_group}" -m 755 "${_app_tmp}/${PROBE_NAME}" "${_app_dir}/${PROBE_NAME}"
  install_darwin_plist "$_plist_path"
  unset ENDPOINT_TOKEN
  echo "[*] Cleaning up tmp directory"
  rm -rf "${_app_tmp}"

}

echo "[+] Detect setup started"
if [[ -z $PRELUDE_ACCOUNT_ID || -z $PRElUDE_ACCOUNT_SECRET ]]
then
    echo "[!] Failed to provide account credentials. Make sure you export PRELUDE_ACCOUNT_ID and PRELUDE_ACCOUNT_SECRET"
    usage
fi

echo "[+] Determining OS"
# determine OS
if [[ ${OSTYPE} == "darwin"* ]]; then
    install_darwin
else
    echo "[!] Unsupported OS!"
    exit 3
fi

echo "[=] Detect setup complete"

# EOF