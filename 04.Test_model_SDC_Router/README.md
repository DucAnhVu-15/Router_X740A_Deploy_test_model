# Test model SDC trên router X740-A

## SDC là gì

SDC (nhận diện thiết bị) đoán **hãng** (`make`), **loại** (`type`) và **đời máy** (`model`) của thiết bị vừa vào mạng,
dựa trên các gói thiết bị tự gửi khi kết nối:

| Nguồn | Đặc trưng lấy ra |
|---|---|
| DHCP | danh sách tham số yêu cầu (PRL), vendor class, hostname |
| DNS | các tên miền thiết bị hỏi |
| mDNS | tên dịch vụ, tên đời máy quảng bá |
| TLS ClientHello (cổng 443) | fingerprint, phiên bản, ALPN, cipher, SNI |
| Địa chỉ MAC | OUI (mã hãng) |

Tổng cộng 12 cột đặc trưng (dạng chuỗi), đưa qua chuỗi suy luận:

```
tcpdump (br-lan) → sdc_agent: gom gói theo MAC → 12 đặc trưng
                 → sdc_packet.ort → nhánh hostname C++ (sdc_hn.bin) → sdc_tail.ort → JSON
```

Agent chạy theo **phiên**: mỗi khi một thiết bị xin DHCP, agent mở phiên cho MAC đó. Phiên kết thúc khi thấy đủ
DHCP, DNS, mDNS và TLS, hoặc khi hết timeout. Lúc đó model chấm một lần và in một dòng JSON.

Model chạy độc lập với IDS (`05.Test_model_IDS`). Trên router, SDC nằm ở `/tmp/sdc`, IDS nằm ở `/tmp/ids`.

## Bộ file chép lên router (`build/router/`)

| File | Vai trò |
|---|---|
| `sdc_agent` | Chương trình chính: đọc pcap từ tcpdump, trích đặc trưng, chạy model, in JSON |
| `sdc_infer` | Kiểm tra model: chạy 1.000 mẫu, so với model gốc, đo thời gian và RAM |
| `sdc_packet.ort`, `sdc_tail.ort` | Hai nửa của model (ONNX Runtime) |
| `sdc_hn.bin` | Dữ liệu cho nhánh hostname |
| `parity_1000.txt` | 1.000 mẫu kèm kết quả mong đợi của model gốc |
| `run_sdc.sh` | Chạy `tcpdump \| sdc_agent` |
| `sdc_monitor.sh` | Đo RAM, CPU của router |
| `checksums.md5` | Kiểm tra file sau khi chép |

`sdc_agent` và `sdc_infer` được link tĩnh cho aarch64 (musl) nên không cần cài thêm gì trên router.

## 1. Chép lên router

`/tmp` của router nằm trên RAM: khởi động lại router là mất, phải chép lại từ đầu.

Tạo thư mục trên router:

```sh
mkdir -p /tmp/sdc
```

Trên PC (cmd), **đứng trong `build\router`** rồi chép:

```bat
cd /d D:\01.AI_Security\Router_X740_A\04.Test_model_SDC_Router\build\router
scp -O sdc_agent sdc_infer sdc_packet.ort sdc_tail.ort sdc_hn.bin run_sdc.sh sdc_monitor.sh parity_1000.txt checksums.md5 admin@192.168.1.1:/tmp/sdc/
```

`-O` dùng giao thức scp cũ vì router không có SFTP.

## 2. Cấp quyền và kiểm tra

Trên router. File chép từ Windows bị mất quyền chạy, nên **bắt buộc phải `chmod +x`**:

```sh
cd /tmp/sdc
chmod +x sdc_agent sdc_infer
md5sum -c checksums.md5
./sdc_infer /tmp/sdc parity_1000.txt
```

- `md5sum -c` phải báo `OK` cho cả 7 file.
- `sdc_infer` phải ra `lech_packet=0 lech_hostname=0 lech_final=0`, tức là chạy trên CPU router cho kết quả
  giống hệt model gốc. Dòng `trung_binh_ms` là thời gian suy luận cho mỗi thiết bị.

## 3. Chạy model

```sh
sh /tmp/sdc/run_sdc.sh 300
```

- Tham số 1: timeout mỗi phiên, tính bằng giây (mặc định 300).
- Tham số 2 (tuỳ chọn): thư mục model, mặc định là thư mục chứa script.
- Để thử, tắt rồi bật lại Wi-Fi trên điện thoại để nó xin DHCP lại. Thiết bị join lại trong vòng 60 s sau khi
  vừa xong phiên sẽ bị bỏ qua.
- Dừng bằng `Ctrl+C`.

Chạy nền để không bị dừng khi rớt SSH (router không có `nohup`):

```sh
(trap '' HUP; sh /tmp/sdc/run_sdc.sh 300 > /tmp/sdc_run.log 2>&1 &)
killall tcpdump        # dừng
```

`run_sdc.sh` chỉ bắt các gói DHCP, DNS, mDNS và gói TLS mở đầu handshake ra cổng 443, nên tốn ít CPU.
Agent bị giới hạn 180 MB bộ nhớ ảo và chạy với `nice -n 10` để không chiếm CPU của router.

## 4. Xem kết quả

Kết quả được ghi thêm vào cuối `/tmp/sdc_results.jsonl` (không ghi đè). Log của tcpdump ở `/tmp/sdc_tcpdump.log`.

```sh
cat /tmp/sdc_results.jsonl
```

Chép về PC:

```bat
scp -O admin@192.168.1.1:/tmp/sdc_results.jsonl .
```

| Trường | Ý nghĩa |
|---|---|
| `window_start` | Thời điểm bắt đầu phiên (UTC) |
| `mac`, `hostname` | Thiết bị. Hostname lấy từ DHCP hoặc `/tmp/dhcp.leases` |
| `make`, `type`, `model` | Kết quả của model |
| `reason` | `complete` (đủ nguồn) hoặc `timeout` (hết giờ) |
| `elapsed_s` | Số giây từ gói DHCP đến lúc chấm |
| `sources` | Các nguồn đã thấy, ví dụ `dhcp+dns+tls`. Càng thiếu nguồn, kết quả càng kém tin cậy |
| `packets`, `infer_ms` | Số gói của phiên và thời gian suy luận |

Muốn xem 12 đặc trưng đưa vào model, thêm `--columns` vào lệnh `sdc_agent` trong `run_sdc.sh`.

## 5. Đo RAM, CPU (tuỳ chọn)

Chạy trong một cửa sổ SSH thứ hai, trong lúc agent đang chạy ở cửa sổ kia.

### Xem RAM liên tục

In một dòng mỗi giây, chạy cho đến khi bấm `Ctrl+C`. Tự nhận agent đang chạy là SDC hay IDS:

```sh
while true; do
  A=$(awk '/MemAvailable/{printf "%.1f",$2/1024}' /proc/meminfo)
  U=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%.1f",(t-a)/1024}' /proc/meminfo)
  OUT="$(date +%H:%M:%S)  dung=${U}MB  con_trong=${A}MB"
  for N in sdc_agent ids_agent tcpdump; do
    P=$(pidof $N)
    [ -n "$P" ] && OUT="$OUT  $N=$(awk '/VmRSS/{printf "%.1f",$2/1024}' /proc/${P%% *}/status)MB"
  done
  echo "$OUT"
  sleep 1
done
```

- `dung`: RAM cả router đang dùng. `con_trong`: RAM còn dùng được (MemAvailable).
- `sdc_agent`, `ids_agent`, `tcpdump`: RAM thật (RSS) của từng tiến trình. Tiến trình nào không chạy thì không hiện.

Cách nhanh hơn là `top`: dòng `Mem:` cho RAM cả router, cột `VSZ` cho từng tiến trình. Bấm `q` để thoát.

### Đo và so sánh bằng script (có CPU, lưu CSV)

```sh
sh /tmp/sdc/sdc_monitor.sh baseline 60 2    # trước khi chạy agent
sh /tmp/sdc/sdc_monitor.sh running 60 2     # trong lúc agent chạy
sh /tmp/sdc/sdc_monitor.sh compare          # so sánh hai lần đo
```

Muốn theo dõi liên tục bằng script thì đặt thời lượng lớn, rồi bấm `Ctrl+C` khi muốn dừng:
`sh /tmp/sdc/sdc_monitor.sh running 86400 1`. Dừng giữa chừng thì không có dòng tổng kết cuối, nhưng số đo vẫn
nằm trong `/tmp/sdc_monitor_running.csv`.

Số đo tham khảo (2026-11-09, `sdc_infer` chạy 1.000 mẫu): nạp model xong 31,6 MB, cao nhất ~51 MB,
trung bình ~25 ms mỗi thiết bị.

## Đổi qua lại với IDS

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
| `scp: stat local "sdc_agent": No such file or directory` | Đang đứng sai thư mục trên PC. Phải `cd` vào `build\router` |
| `nice: can't execute '/tmp/sdc/sdc_agent': Permission denied` | Chưa `chmod +x sdc_agent sdc_infer` |
| `md5sum` báo `FAILED` | File chép lỗi hoặc là bản cũ. Chép lại file đó |
| Chạy xong mà không có dòng JSON nào | Không có thiết bị nào xin DHCP trong lúc chạy. Bật/tắt Wi-Fi một thiết bị |
| `0 packets captured` ngay khi bắt đầu | Agent không chạy được (xem dòng lỗi phía trên), tcpdump dừng theo |

## Thư mục

| Đường dẫn | Nội dung |
|---|---|
| `agent/` | Mã C++ (`sdc_agent`, `sdc_infer`, `feature_extract`, `hostname_engine`) và các script chạy trên router |
| `build/router/` | Bộ file chép lên router |
| `build/ort/` | Model `.ort`, `sdc_hn.bin`, bộ test `parity_cases.txt` |
| `build/test/` | pcap thử và kết quả mong đợi |
| `model_split/` | Script Python tách model, tạo bộ test, tạo pcap thử |
| `toolchain/` | Script build, chạy trong WSL |

## Build lại (WSL)

Chỉ cần khi sửa mã C++ hoặc đổi model. Toolchain, mã nguồn ONNX Runtime và QEMU nằm ở `~/sdc-router`.

```bash
cd /mnt/d/01.AI_Security/Router_X740_A/04.Test_model_SDC_Router/toolchain
bash setup_toolchain.sh aarch64                                  # toolchain musl của Bootlin
bash fetch_ort.sh                                                # mã nguồn ONNX Runtime 1.28.0
bash build_ort_arm64.sh ../build/ort/required_operators.config   # ORT rút gọn, link tĩnh
bash build_agent.sh                                              # tạo build/sdc_infer, build/sdc_agent
bash fetch_qemu.sh                                               # qemu-aarch64 để chạy thử trên PC
bash test_agent.sh ../build/test/obs.pcap ../build/test/agent.jsonl
bash package_router.sh                                           # gom vào build/router, tạo checksum
```

Các bước tải và build ORT chỉ cần chạy một lần. Nếu chỉ sửa mã agent thì chạy `build_agent.sh`, `test_agent.sh`
rồi `package_router.sh`.

## Khác với model gốc

- `sdc_os.onnx` được tách bằng `model_split/split_model.py` thành `sdc_packet` (phần trước nhánh hostname) và
  `sdc_tail` (phần sau). Nhánh hostname được viết lại bằng C++ (`hostname_engine.cpp`, dữ liệu trong `sdc_hn.bin`)
  để chạy được với bản ONNX Runtime rút gọn.
- Độ khớp với model gốc được kiểm bằng `sdc_infer` trên `parity_1000.txt` (bước 2).
- tcpdump chỉ bắt gói TLS ra cổng 443 nếu là gói mở đầu handshake hoặc có cờ PSH, để đỡ tốn CPU khi tải nhiều.
