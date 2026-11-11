@echo off
REM Chep build\router len /tmp/ids cua router, chmod va kiem tra checksum. Chi hoi mat khau 1 lan.
REM Chay tren PC (cmd), dung o thu muc nao cung duoc:
REM   D:\01.AI_Security\Router_X740_A\05.Test_model_IDS\toolchain\deploy_router.bat
REM IDS dang chay tren router se bi dung (killall tcpdump) de thay duoc ids_agent.
setlocal
set ROUTER=admin@192.168.1.1
set FILES=ids_agent ids_model.ort run_ids.sh capture_ids.sh check_router.sh ids_monitor.sh selftest.pcap selftest.expected checksums.md5

pushd "%~dp0..\build\router" || exit /b 1
"%SystemRoot%\System32\tar.exe" --format ustar -cf - %FILES% | ssh %ROUTER% "killall tcpdump 2>/dev/null; sleep 1; mkdir -p /tmp/ids && cd /tmp/ids && tar -xf - && chmod +x ids_agent && md5sum -c checksums.md5 && echo XONG: da chep vao /tmp/ids"
set RESULT=%ERRORLEVEL%
popd
exit /b %RESULT%
