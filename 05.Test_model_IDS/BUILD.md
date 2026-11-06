# Build IDS cho router

Chạy trong cmd trên PC, không chạy trong phiên SSH của router. Cần có trong WSL: `~/sdc-router` (toolchain aarch64 musl, ONNX Runtime đã build, QEMU).

```bat
cd /d D:\01.AI_Security\Router_X740_A\05.Test_model_IDS
```

## Lệnh build

```bat
REM 1. Chuyen model, chi can khi doi model.onnx
python toolchain\convert_model.py

REM 2. Build ids_agent, can khi sua code hoac o lan build dau
wsl.exe -d Ubuntu --exec bash "/mnt/d/01.AI_Security/Router_X740_A/05.Test_model_IDS/toolchain/build_ids.sh"

REM 3. Lay pcap tu kiem tra, chi can lan dau
cd tools && python -W ignore compare_agent.py --lab 3 && cd ..

REM 4. Dong goi vao build\router\
wsl.exe -d Ubuntu --exec bash "/mnt/d/01.AI_Security/Router_X740_A/05.Test_model_IDS/toolchain/package_router.sh"
```

Bước 4 phải in dòng `thu tu dac trung khop deploy_config.json: 97`.

Đổi sang run khác thì truyền thư mục run: `python toolchain\convert_model.py model\<run_id>`. Khi đó phải sửa thêm `kDefaultThreshold`
trong `agent/ids_agent.cpp` và đường dẫn `deploy_config.json` trong `toolchain/package_router.sh`.

## Chép xuống router

Mỗi lệnh hỏi mật khẩu một lần.

```bat
ssh admin@192.168.1.1 "rm -rf /tmp/ids"
scp -O -r build\router admin@192.168.1.1:/tmp/ids
```

Cách chạy và test: xem [README.md](README.md).
