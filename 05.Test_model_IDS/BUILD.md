# Build IDS cho router

Mọi lệnh chạy trong **cmd trên PC**, không chạy trong cửa sổ SSH của router. Đứng ở thư mục nào cũng được.
Cần có trong WSL: `~/sdc-router` (toolchain aarch64 musl, ONNX Runtime đã build, QEMU).

## Khi có model mới: 2 lệnh

**Bước 0.** Chép thư mục run mới (có `model.onnx` và `deploy_config.json`) vào
`D:\01.AI_Security\Router_X740_A\05.Test_model_IDS\model\<run_id>\`.

**Bước 1. Build và đóng gói:**

```bat
D:\01.AI_Security\Router_X740_A\05.Test_model_IDS\toolchain\new_model.bat
```

Không truyền gì thì script lấy thư mục run mới nhất trong `model\`. Muốn chọn run cụ thể thì thêm tên run:
`...\new_model.bat 20261111_1058`.

Script tự làm 4 việc, lỗi ở đâu thì dừng ở đó và in `LOI: ...`:

1. Chuyển `model.onnx` sang `build\ort\ids_model.ort`, kiểm tra xác suất không bị lệch.
2. Kiểm tra model chỉ dùng `TreeEnsembleClassifier`, là op duy nhất mà ONNX Runtime trên router có.
3. Build `ids_agent`. Ngưỡng mặc định lấy từ `deploy_config.json`, không cần sửa code.
4. Đóng gói vào `build\router`, tạo lại `selftest.expected` và `checksums.md5`. Kiểm tra binary khớp
   `deploy_config.json` về thứ tự 97 đặc trưng, 4 lớp, cửa sổ và ngưỡng.

Thành công thì dòng cuối là `XONG model <run_id>`.

**Bước 2. Chép lên router**, hỏi mật khẩu một lần:

```bat
D:\01.AI_Security\Router_X740_A\05.Test_model_IDS\toolchain\deploy_router.bat
```

Script dừng IDS đang chạy, tạo `/tmp/ids`, chép 9 file cần thiết, `chmod +x ids_agent` và kiểm tra checksum.
Thành công thì in `: OK` cho từng file và dòng `XONG: da chep vao /tmp/ids`. Không chép pcap test lớn trong
`build\router` (`recon.pcap` khoảng 1,8 GB).

**Bước 3. Trên router** (cửa sổ SSH):

```sh
cd /tmp/ids
sh check_router.sh
sh run_ids.sh
```

Lúc khởi động, agent in `nguong=` đúng ngưỡng của model mới. Muốn thử ngưỡng khác mà không build lại:
`THRESHOLD=0.9 sh run_ids.sh`.

Cửa sổ router báo `getcwd: No such file or directory` là do `/tmp/ids` vừa được tạo lại. Gõ `cd /tmp/ids` là xong.
`/tmp` của router nằm trên RAM: khởi động lại router thì chạy lại bước 2.

## Khi `new_model.bat` báo lỗi

| Thông báo | Nguyên nhân, cách xử lý |
|---|---|
| `DLL load failed ... Application Control policy has blocked this file` | Windows (Smart App Control) chặn DLL của `ml_dtypes`. Cho phép file đó trong Windows Security → App & browser control |
| `model can op khac TreeEnsembleClassifier` | Model không phải dạng cây (HGB/RandomForest). Phải build lại ONNX Runtime trong `~/sdc-router` với op mới |
| `thu tu dac trung khac`, `lop khac`, `cua so khac` | Model mới dùng đặc trưng hoặc cửa sổ khác. Phải sửa phần tính đặc trưng trong `agent/ids_agent.cpp`, thay model không thôi là không đủ |
| `xac suat thay doi` | Đổi opset làm lệch kết quả model, không dùng được file `.ort` này |

## Chỉ sửa code, không đổi model

```bat
wsl.exe -d Ubuntu --exec bash "/mnt/d/01.AI_Security/Router_X740_A/05.Test_model_IDS/toolchain/build_ids.sh" 20261111_1058
wsl.exe -d Ubuntu --exec bash "/mnt/d/01.AI_Security/Router_X740_A/05.Test_model_IDS/toolchain/package_router.sh" 20261111_1058
```

Rồi chạy `deploy_router.bat`. Nhớ truyền `run_id` cho `build_ids.sh`, nếu không ngưỡng sẽ lấy giá trị mặc định ghi trong
`ids_agent.cpp`, và `package_router.sh` sẽ báo lệch ngưỡng.

Cách chạy và test trên router: xem [README.md](README.md).
