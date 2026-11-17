@echo off
REM Dua model moi vao IDS: kiem tra, chuyen sang .ort, build ids_agent, dong goi vao build\router.
REM Chay tren PC (cmd), dung o thu muc nao cung duoc:
REM   D:\01.AI_Security\Router_X740_C\05.Test_model_IDS\toolchain\new_model.bat [run_id]
REM Bo trong run_id thi lay thu muc moi nhat trong model\. Xong thi chay deploy_router.bat de chep len router.
setlocal
for %%i in ("%~dp0..") do set "PROJECT=%%~fi"
REM Duong dan WSL tinh tu vi tri cua script, chep sang thu muc khac van dung.
for /f "delims=" %%p in ('wsl.exe -d Ubuntu --exec wslpath -a "%PROJECT%"') do set "WSL_PROJECT=%%p"
if not defined WSL_PROJECT (echo LOI: khong doi duoc %PROJECT% sang duong dan WSL & exit /b 1)
set "RUN=%~1"
if "%RUN%"=="" for /f "delims=" %%d in ('dir /b /ad /o-n "%PROJECT%\model"') do if not defined RUN set "RUN=%%d"
set "RUN_DIR=%PROJECT%\model\%RUN%"

echo === Model: %RUN%
if not exist "%RUN_DIR%\model.onnx" (echo LOI: khong co %RUN_DIR%\model.onnx & exit /b 1)
if not exist "%RUN_DIR%\deploy_config.json" (echo LOI: khong co %RUN_DIR%\deploy_config.json & exit /b 1)

echo === 1/4 Chuyen model sang .ort
python "%PROJECT%\toolchain\convert_model.py" "%RUN_DIR%" || (echo LOI: chuyen model that bai & exit /b 1)

echo === 2/4 Kiem tra op ma ONNX Runtime tren router ho tro
findstr /v /b "#" "%PROJECT%\build\ort\ids_model.required_operators.config" | findstr /v /x /c:"ai.onnx.ml;3;TreeEnsembleClassifier" && (echo LOI: model can op khac TreeEnsembleClassifier, phai build lai ORT & exit /b 1)
echo chi can TreeEnsembleClassifier: OK

echo === 3/4 Build ids_agent voi nguong cua run %RUN%
wsl.exe -d Ubuntu --exec bash "%WSL_PROJECT%/toolchain/build_ids.sh" "%RUN%" || (echo LOI: build that bai & exit /b 1)

echo === 4/4 Dong goi vao build\router
wsl.exe -d Ubuntu --exec bash "%WSL_PROJECT%/toolchain/package_router.sh" "%RUN%" || (echo LOI: dong goi that bai & exit /b 1)

echo.
echo XONG model %RUN%. Chep len router: "%PROJECT%\toolchain\deploy_router.bat"
endlocal
