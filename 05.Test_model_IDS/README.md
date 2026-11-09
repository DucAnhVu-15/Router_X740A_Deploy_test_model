# Test model IDS trên router X740-A

Chạy riêng model IDS, không liên quan SDC: `tcpdump | ids_agent` trên router, xuất cảnh báo JSON.
File cần chép đã nằm sẵn ở `build/router/` (6,7 MB).

## 1. Chép lên router

`/tmp` của router nằm trên RAM: khởi động lại router là mất, phải chép lại từ đầu.
Nếu `ls /tmp/ids` vẫn còn file thì bỏ qua bước này.

Trên router, dừng model đang chạy (nếu có) và tạo thư mục:

```sh
killall tcpdump
mkdir -p /tmp/ids
```

Trên PC (cmd), **đứng trong `build\router`** rồi chép:

```bat
cd /d D:\01.AI_Security\Router_X740_A\05.Test_model_IDS\build\router
scp -O ids_agent ids_model.ort run_ids.sh capture_ids.sh check_router.sh ids_monitor.sh selftest.pcap selftest.expected checksums.md5 admin@192.168.1.1:/tmp/ids/
```

`-O` dùng giao thức scp cũ vì router không có SFTP. Không dùng `scp -r build/router .../tmp/ids` khi `/tmp/ids`
đã tồn tại, vì khi đó file sẽ vào `/tmp/ids/router`.

Trên router. File chép từ Windows bị mất quyền chạy, nên **bắt buộc phải `chmod +x`**:

```sh
cd /tmp/ids && chmod +x ids_agent && md5sum -c checksums.md5
```

`md5sum -c` phải báo `OK` cho tất cả file.

## 2. Kiểm tra router

Trên router chạy lệnh dưới, đồng thời từ máy tấn công chạy `ping -c 15 192.168.1.182`:

```sh
sh check_router.sh 192.168.1.236 192.168.1.182
```

Cần cả hai dòng KET LUAN đều đạt:

- `thay ca hai chieu`: tcpdump thấy traffic giữa hai máy. Nếu không, tăng tốc phần cứng hoặc đường đi đang
  né `br-lan`, và model sẽ thiếu đặc trưng.
- `giong het ban QEMU`: model cho kết quả đúng trên CPU thật.

## 3. Đo báo động giả (chưa tấn công)

Nên chạy nền, vì flood có thể làm rớt phiên SSH:

```sh
(trap '' HUP; sh run_ids.sh 1800 > /tmp/ids_run.log 2>&1 &)
sh ids_monitor.sh running 60 2     # tuỳ chọn: RAM, CPU
```

Dừng sớm bằng `killall tcpdump`. Mỗi lần chạy ghi đè `ids_windows.csv`, nên chép về trước khi chạy lần sau.

Tham số của `run_ids.sh`:

| Cách gọi | Ý nghĩa |
|---|---|
| `sh run_ids.sh 600` | Chạy 600 s rồi tự dừng. `0` hoặc bỏ trống: chạy đến khi `Ctrl+C` |
| `INTERVAL=3 sh run_ids.sh 600` | In log mỗi 3 s (mặc định 5) |
| `LIVE=1 sh run_ids.sh 600` | Hiện bảng cập nhật tại chỗ, giống `top` |
| `EXCLUDE=192.168.1.1 sh run_ids.sh 600` | Bỏ qua một địa chỉ IP |

Xem RAM liên tục: mở SSH thứ hai, chạy vòng lặp ở mục 5 trong `04.Test_model_SDC_Router/README.md`
(tự nhận `ids_agent`), hoặc dùng `top`.

## 4. Chạy tấn công thử

Chỉ chạy trong lab, từ `192.168.1.236` vào `192.168.1.182`. Giữ `run_ids.sh` chạy, các đợt cách nhau trên 60 s
để không bị gộp. DoS để tốc độ vừa phải vì router vừa chuyển gói vừa chạy model.

| Kịch bản | Lệnh | Kỳ vọng theo test của run |
|---|---|---|
| Quét SYN | `sudo nmap -Pn -n -sS --top-ports 1000 -T4 192.168.1.182` | `recon` |
| Quét FIN/NULL/XMAS | `sudo nmap -Pn -n -sF --top-ports 200 192.168.1.182` (đổi `-sN`, `-sX`) | `recon` |
| Quét ACK | `sudo nmap -Pn -n -sA --top-ports 200 192.168.1.182` | `recon` |
| Quét UDP | `sudo nmap -Pn -n -sU --top-ports 100 192.168.1.182` | `recon`, 87,5% task |
| Quét ARP | `sudo arp-scan 192.168.1.0/24` | `recon` |
| **Ping sweep** | `sudo nmap -sn -PE 192.168.1.0/24` | **Trượt: 0/118 task, không phải lỗi agent** |
| Brute-force SSH | `hydra -L users.txt -P pass.txt -t 4 ssh://192.168.1.182` | `bruteforce` |
| SYN flood | `sudo timeout 20 hping3 -S -p 80 -i u500 192.168.1.182` | `dos` |
| UDP flood | `sudo timeout 20 hping3 --udp -p 53 -i u500 192.168.1.182` | `dos`, 79% cửa sổ |
| ICMP flood | `sudo timeout 20 hping3 -1 -i u500 192.168.1.182` | `dos`, 69% cửa sổ |
| ACK, FIN, RST flood | như SYN, đổi `-S` thành `-A`, `-F`, `-R` | `dos` |

Cảnh báo in ra `/tmp/ids_run.log` và `/tmp/ids_alerts.jsonl`. `attack_end` chỉ xuất hiện sau khi hết báo động 60 s.

Mỗi 30 s agent in dòng `[stats]`. Khi dừng, xem cuối log: nếu `packets dropped by kernel` lớn hơn 0 thì
kết quả của đoạn đó thiếu gói, đặc biệt lúc flood.

## 5. Chép kết quả về PC và xem

```powershell
scp -O admin@192.168.1.1:/tmp/ids_windows.csv admin@192.168.1.1:/tmp/ids_alerts.jsonl build/
python tools/summarize_run.py build/ids_windows.csv
```

## Cách khác: bắt pcap rồi chấm trên PC

Dùng khi muốn giữ lại gói để phân tích, hoặc để đối chiếu với kết quả chạy trực tiếp:

```sh
sh capture_ids.sh 300        # trên router: bắt 300 s, tối đa 300.000 gói
```

```powershell
scp -O admin@192.168.1.1:/tmp/ids_capture.pcap build/
python tools/pkt_features_ref.py build/ids_capture.pcap --out build/windows.csv
```

## Đổi qua lại với SDC

IDS nằm ở `/tmp/ids`, SDC nằm ở `/tmp/sdc` (xem `04.Test_model_SDC_Router/README.md`).

```sh
sh /tmp/ids/run_ids.sh 600     # chạy IDS
sh /tmp/sdc/run_sdc.sh 300     # chạy SDC
killall tcpdump                # dừng model đang chạy
```

File kết quả không đè nhau (`/tmp/ids_*` và `/tmp/sdc_*`). Mỗi lần chỉ nên chạy một model, vì `killall tcpdump`,
kể cả lệnh hẹn giờ trong `run_ids.sh`, dừng tcpdump của cả hai.

## Lỗi thường gặp

| Lỗi | Nguyên nhân, cách sửa |
|---|---|
| `scp: stat local "ids_agent": No such file or directory` | Đang đứng sai thư mục trên PC. Phải `cd` vào `build\router` |
| `build/router: No such file or directory` | Chạy `scp -r build/router` từ trong `build\router`. Dùng lệnh chép từng file ở mục 1 |
| `nice: can't execute '/tmp/ids/ids_agent': Permission denied` | Chưa `chmod +x ids_agent` |
| `md5sum` báo `FAILED` | File chép lỗi hoặc là bản cũ. Chép lại file đó |

## Thư mục

| Đường dẫn | Nội dung |
|---|---|
| `agent/` | `ids_agent.cpp` và các script chạy trên router |
| `build/router/` | Bộ file chép lên router |
| `tools/pkt_features_ref.py` | Chấm pcap trên PC, tính đặc trưng theo tài liệu |
| `tools/validate_lab.py` | Đối chiếu với `test_per_task.csv` trên pcap lab |
| `tools/compare_agent.py` | So `ids_agent` với bản Python từng đặc trưng |
| `toolchain/` | `build_ids.sh`, rồi `package_router.sh`, chạy trong WSL |

## Khác với model gốc

- `ids_model.ort` chuyển từ `model.onnx`, chỉ đổi khai báo opset `ai.onnx.ml` từ 1 lên 3 để dùng bản ONNX Runtime
  rút gọn. Xác suất giống hệt trên 200.000 mẫu ngẫu nhiên.
- Đặc trưng viết lại từ `feature_pipeline_bruteforce_recon_dos.md`, không phải `pkt_features.py` gốc (không có
  trong thư mục này).
- Ngữ cảnh 60/300 s tính theo khối 1 giây, nên đếm có thể lệch ở mép khoảng.
- Mỗi tập phần tử giữ tối đa 70.000 mục, cao hơn mọi ngưỡng của model. Khi đầy thì bỏ mục cũ nhất.
