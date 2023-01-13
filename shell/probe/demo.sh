#!/bin/bash

GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # No Color

PRELUDE_API=${PRELUDE_API:="https://api.preludesecurity.com"}
PRELUDE_TOKEN=$1

sys=$(uname -s)-$(uname -m)
id="b74ad239-2ddd-4b1e-b608-8397a43c7c54"
dos=$(echo $sys | tr '[:upper:]' '[:lower:]')

function check_relevance {
    echo -e "${GREEN}[✓] Result: Success - server or workstation detected${NC}"
}

function download_test {
    temp=$(mktemp)
    location=$(curl -sfSL -w %{url_effective} -o $temp -H "token:${PRELUDE_TOKEN}" -H "dos:${dos}" -H "id:${id}" $PRELUDE_API)
    test=$(echo $location | grep -o '[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}' | head -n 1)
    if [ -z "$test" ];then
        echo -e "${RED}[!] Failed to download test${NC}"
        exit 1
    else
        echo -e "${GREEN}[✓] Wrote to temporary file: ${temp}${NC}"
        chmod +x $temp
    fi
}

function execute_test {
    $temp
    test_result=$?
    echo
    if [ "$test_result" = 100 ];then
        echo -e "${GREEN}[✓] Result: control test passed${NC}"
    else
        echo -e "${RED}[!] Result: control test failed${NC}"
    fi
}

function execute_cleanup {
    $temp -cleanup
    cleanup_result=$?
    echo
    echo -e "${GREEN}[✓] Clean up is complete${NC}"
}

function post_results {
    max=$(( $test_result > $cleanup_result ? $test_result : $cleanup_result ))
    dat=${test}:${max}
    curl -sfSL -H "token:${PRELUDE_TOKEN}" -H "dos:${dos}" -H "dat:${dat}" $PRELUDE_API
}

function install_probe {
    echo "[+] Downloading installation script"
    temp=$(mktemp)
    curl -sfSL -o $temp -H "token:${PRELUDE_TOKEN}" -H "dos:${dos}" $PRELUDE_API/download/install
    test -s "$temp" || {
        echo -e "${RED}[!] Failed to download installation script${NC}"
        exit 1
    }
    chmod +x $temp
    echo
    read -p "Enter your Prelude Account ID: " ACCOUNT_ID
    read -p "Enter your Prelude Account token: " ACCOUNT_TOKEN
    sudo $temp -a $ACCOUNT_ID -s $ACCOUNT_TOKEN
}

echo
echo "###########################################################################################################"
echo
echo "Welcome to Prelude!"
echo
echo "Malicious files are used to gain entry and conduct cyberattacks against corporate systems through seemingly"
echo "innocuous email attachments or direct downloads. For example - a malicious macro was used by the BlueNoroff"
echo "group in a ransomware attack (Dec. 2022)"
echo
echo "Rules are specific defensive practices that are meant to protect you from certain types of malicious behavior."
echo "Prelude runs tests designed to challenge the effectiveness of these defenses and check if your system is"
echo "configured to restrict malicious behavior from happening"
echo
echo "Rule: Malicious files should quarantine when written to disk"
echo "Test: Will your computer quarantine a malicious Office document?"
echo
echo "[+] ATT&CK mappings: T1204.002"
echo
echo "###########################################################################################################"
echo
read -p "Press ENTER to continue"
echo
echo "Starting test at: $(date +"%T")"
echo
echo "-----------------------------------------------------------------------------------------------------------"
echo "[0] Conducting relevance test"
echo && sleep 3
check_relevance
echo "-----------------------------------------------------------------------------------------------------------"
echo "[1] Downloading test"
echo
download_test
echo "-----------------------------------------------------------------------------------------------------------"
echo "[2] Executing test"
echo && sleep 3
execute_test
echo "-----------------------------------------------------------------------------------------------------------"
echo "[3] Running cleanup"
echo && sleep 3
execute_cleanup
post_results
echo
echo "###########################################################################################################"
echo
if [ "$test_result" = 100 ];then
    echo -e "${GREEN}[✓] Good job! Your computer detected and responded to a malicious Office document dropped on "
    echo -e "the disk${NC}"
else
    echo -e "${RED}[!] This test was able to verify the existence of this vulnerability on your machine, as well as drop"
    echo "a malicious Office document on the disk. If you have security controls in place that you suspect should"
    echo -e "have protected your host, please review the logs${NC}"
fi
echo
echo "###########################################################################################################"
echo
read -p "[Optional] Would you like to install the probe on this endpoint? This will allow you to run this test, and \
others, on a continuous schedule (y/n) " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]];then
    echo
    install_probe
    extra_msg="and enable continuous scheduling for this test"
fi
echo
echo
echo "[*] Return to the Prelude Platform to view your results $extra_msg"
echo