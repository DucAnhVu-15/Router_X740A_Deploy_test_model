# Test model SDC trên router X740-C

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

## Đổi sang model mới (cách nhanh)

Mỗi bản model mới là một thư mục `model_origin\<run>\release\` gồm `sdc_os.onnx`, `sdc_os_contract.json`,
`manifest.json`. Trên PC (cmd hoặc PowerShell):

```bat
cd /d D:\01.AI_Security\Router_X740_C\04.Test_model_SDC_Router
python deploy_model.py model_origin\20261116_093834
python deploy_model.py --push-only
```

- Lệnh 1 build lại toàn bộ `build/router/` từ model, khoảng 11 phút. Chỉ thay đường dẫn model là đủ.
  Script tự dừng và báo lỗi nếu bản chạy trên CPU ARM (QEMU) lệch dù chỉ một dòng so với model gốc,
  khi đó không đóng gói gì.
- Lệnh 2 chép bộ file vừa build lên router `admin@192.168.1.1`, dừng `sdc_agent` đang chạy (nếu có),
  kiểm md5 và chạy `sdc_infer` trên router. Có thể hỏi mật khẩu 3 lần (dùng SSH key thì không hỏi).
  Router khác: `--push-only root@192.168.1.254`. Muốn build xong chép luôn: thêm `--push` vào lệnh 1.
- Thử nhanh: `--parity-rows 1000` chỉ đối chiếu 1.000 dòng trên QEMU thay vì cả ~15.000 dòng.
- Router đang chạy bản nào: `cat /tmp/sdc/model_version.txt`.

Các bước `deploy_model.py` làm, theo thứ tự:

| Bước | Việc | Kết quả |
|---|---|---|
| 1 | Kiểm sha256 của `sdc_os.onnx` và `sdc_os_contract.json` theo `manifest.json` | |
| 2 | `model_split/split_model.py`: tách model | `build/model/` |
| 3 | `onnxruntime.tools.convert_onnx_models_to_ort --optimization_style Fixed` | `build/ort/*.ort`, `required_operators.config` |
| 4 | `model_split/export_hostname.py`: xuất nhánh hostname | `build/ort/sdc_hn.bin` |
| 5 | `model_split/make_parity.py`: chạy model gốc trên `build/test/parity_inputs.txt`, kiểm hai nửa model tách | `build/ort/parity_cases.txt` |
| 6 | WSL `toolchain/build_router.sh`: build lại ORT nếu danh sách op đổi, link agent, đối chiếu trên QEMU, chạy pcap thử, đóng gói | `build/router/` |

Nếu model mới cần op mà bản ONNX Runtime hiện có không có, bước 6 tự build lại ORT (lâu hơn nhiều).
Nếu model đổi cấu trúc nhánh hostname hoặc thứ tự 12 cột, bước 4, 5 hoặc 6 sẽ báo lỗi: khi đó phải sửa
`hostname_engine.cpp` / `feature_extract.cpp` chứ không chỉ thay model.

Bản router của model cũ (`20261104_151438_release`) được giữ ở `build/backup_20261104_151438_release/`.

## Bộ file chép lên router (`build/router/`)

| File | Vai trò |
|---|---|
| `sdc_agent` | Chương trình chính: đọc pcap từ tcpdump, trích đặc trưng, chạy model, in JSON |
| `sdc_infer` | Kiểm tra model: chạy 1.000 mẫu, so với model gốc, đo thời gian và RAM |
| `sdc_packet.ort`, `sdc_tail.ort` | Hai nửa của model (ONNX Runtime) |
| `sdc_hn.bin` | Dữ liệu cho nhánh hostname |
| `parity_1000.txt` | 1.000 mẫu kèm kết quả mong đợi của model gốc |
| `run_sdc.sh` | Chạy `tcpdump \| sdc_agent` |
| `sdc_service.sh` | Chạy `run_sdc.sh` dưới nền, không bị dừng khi rớt SSH (start/stop/status/log) |
| `sdc_monitor.sh` | Đo RAM, CPU của router |
| `model_version.txt` | Bản model (release, sha256, thời điểm build) |
| `checksums.md5` | Kiểm tra file sau khi chép |

`sdc_agent` và `sdc_infer` được link tĩnh cho aarch64 (musl) nên không cần cài thêm gì trên router.

## 1. Chép lên router

`/tmp` của router nằm trên RAM: khởi động lại router là mất, phải chép lại từ đầu.
`python deploy_model.py --push-only` làm luôn bước 1 và 2 dưới đây. Chép tay:

Tạo thư mục trên router:

```sh
mkdir -p /tmp/sdc
```

Trên PC (cmd), **đứng trong `build\router`** rồi chép:

```bat
cd /d D:\01.AI_Security\Router_X740_C\04.Test_model_SDC_Router\build\router
scp -O sdc_agent sdc_infer sdc_packet.ort sdc_tail.ort sdc_hn.bin run_sdc.sh sdc_service.sh sdc_monitor.sh parity_1000.txt model_version.txt checksums.md5 root@192.168.1.1:/tmp/sdc/
```

Nếu agent đang chạy thì dừng trước (`killall sdc_agent`): ghi đè file `.ort` đang được agent dùng sẽ làm agent lỗi.

`-O` dùng giao thức scp cũ vì router không có SFTP.

## 2. Cấp quyền và kiểm tra

Trên router. File chép từ Windows bị mất quyền chạy, nên **bắt buộc phải `chmod +x`**:

```sh
cd /tmp/sdc
chmod +x sdc_agent sdc_infer
md5sum -c checksums.md5
./sdc_infer /tmp/sdc parity_1000.txt
```

- `md5sum -c` phải báo `OK` cho cả 10 file.
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

### Chạy nền (nên dùng khi chạy lâu)

Chạy `run_sdc.sh` trực tiếp trong cửa sổ SSH thì khi SSH rớt, cả `tcpdump` lẫn `sdc_agent` chết theo. Máy hiện
`Connection to 192.168.1.1 closed by remote host` là trường hợp này. Agent chỉ in khi có kết quả, nên cửa sổ có thể
im lặng nhiều phút; router có thể coi đó là phiên SSH không hoạt động và tự ngắt. Chạy nền thì agent không phụ
thuộc SSH:

```sh
sh /tmp/sdc/sdc_service.sh start 300   # chạy nền, timeout 300 s
sh /tmp/sdc/sdc_service.sh status      # đang chạy không, RAM agent, số kết quả
sh /tmp/sdc/sdc_service.sh log         # xem log trực tiếp; Ctrl+C chỉ thoát xem, agent vẫn chạy
sh /tmp/sdc/sdc_service.sh stop        # dừng; phiên đang gom dở được chấm luôn (reason "eof")
```

- Log, gồm kết quả và thông báo lỗi, nằm ở `/tmp/sdc_run.log`. Kết quả nằm ở `/tmp/sdc_results.jsonl`, observation ở
  `/tmp/sdc_observations.jsonl`. Rớt SSH thì chỉ cần SSH lại rồi chạy `status` hoặc `log`.
- `stop` chỉ dừng tcpdump của agent này, không đụng tcpdump của chương trình khác như IDS.
- Khởi động lại router thì `/tmp` bị xoá, agent không tự chạy lại.

Nếu SSH lại mà `status` báo `khong chay`, cần kiểm tra router có khởi động lại không và có tiến trình nào bị giết vì
hết RAM không:

```sh
uptime; ls /tmp/sdc                                    # uptime ngắn hoặc mất /tmp/sdc: router đã khởi động lại
logread | grep -i -E 'oom|killed|dropbear' | tail -20  # có "Out of memory"/"Killed process": hết RAM
tail -20 /tmp/sdc_run.log                              # agent tự báo lỗi gì trước khi dừng
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

### Log observation của từng lần suy luận

Mỗi lần chấm một thiết bị, agent ghi thêm một dòng JSON vào `/tmp/sdc_observations.jsonl`. Dòng này cùng định
dạng với `device_observations.jsonl` của bộ thu thập (`mac`, `hostname`, `dhcp`, `dns`, `mdns`, `tls`), thêm khoá
`inference` ở cuối:

```json
{"mac":"b2:ce:e2:0e:41:dc","hostname":"Tab-S9-FE-cua-Thang",
 "dhcp":[{"timestamp":"2026-11-11T01:28:57.373Z","transaction_id":659102737,"message_type":3,"message_name":"REQUEST",
          "hostname":"Tab-S9-FE-cua-Thang","vendor_class_id":"android-dhcp-16","parameter_request_list":[1,3,6,...],
          "options":[{"code":53,"value_hex":"03"},...]}, {... "message_name":"ACK" ...}],
 "dns":[{"timestamp":"...","response":false,"response_code":0,"questions":[{"name":"www.google.com","type":1}],
         "answers":[],"authorities":[],"additionals":[]}, ...],
 "mdns":[...], "tls":[{"timestamp":"...","legacy_version":"0303","server_names":["mtalk.google.com"],"alpn":[],
                       "cipher_suites":[4865,4866,...]}, ...],
 "inference":{"window_start":"2026-11-11T01:28:57Z","reason":"complete","elapsed_s":32,
              "make":"Samsung","type":"Smartphone/Tablet","model":"Samsung Galaxy Tab S9 FE","infer_ms":24.1,
              "packets":{"dhcp":2,"dns":118,"mdns":0,"tls":64},"columns":{"dhcp_prl":"...", ...}}}
```

- Chỉ giữ **64 bản ghi đầu** mỗi nguồn, giống bộ thu thập. `inference.packets` là số gói thật agent đã dùng để tính
  feature. Số này có thể lớn hơn 64.
- `dhcp` có cả gói OFFER/ACK của router, giống bộ thu thập. Các gói này chỉ để xem, không tính vào feature.
- `dns` chỉ có truy vấn của thiết bị, vì tcpdump chỉ bắt `udp dst port 53`.
- `mdns`: `value` của A là địa chỉ IP, của PTR là tên miền. TXT nối các chuỗi bằng `;`, ký tự điều khiển đổi
  thành `?`. Loại khác để trống, xem `rdata_hex`. Bit cache-flush đã bỏ khỏi `class`.
- `inference.columns` là đúng 12 cột đã đưa vào model.
- Đổi chỗ ghi: `SDC_OBS=/tmp/x.jsonl sh /tmp/sdc/run_sdc.sh 300`. Tắt log: `SDC_OBS= sh /tmp/sdc/run_sdc.sh 300`.
- File nằm trong `/tmp` (RAM), mỗi dòng khoảng vài chục KB. Xem xong thì xoá: `rm /tmp/sdc_observations.jsonl`.

Xem dòng mới nhất trên router: `tail -n 1 /tmp/sdc_observations.jsonl`. Dễ đọc hơn là chép về PC rồi kiểm tra:

```bat
scp -O admin@192.168.1.1:/tmp/sdc_observations.jsonl .
python model_split\check_observations.py sdc_observations.jsonl --model model_origin\20261116_093834\release\sdc_os.onnx
```

`check_observations.py` in mỗi lần suy luận một dòng (MAC, kết quả, số bản ghi từng nguồn). Script tính lại 12 cột
từ bản ghi thô bằng `feature_row()` của bên train và so với `inference.columns`. Có `--model` thì chạy lại model
gốc và so nhãn. Lệch cột khi một nguồn quá 64 gói là bình thường, vì agent tính trên nhiều gói hơn phần được ghi.

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

RSS của `sdc_agent` tăng một chút sau mỗi thiết bị mới trong thời gian đầu, rồi đứng yên. Đây không phải rò bộ nhớ:

- Regex trong hostname engine và trong model dựng bảng tra dần theo hostname, chuỗi mDNS mới.
- Phần file model mới được đọc lần đầu cũng tính vào RSS. Phần này là file `/tmp` đã nằm sẵn trong RAM, không tốn thêm.
- Heap giữ lại mức của lần suy luận lớn nhất để dùng lại.

Thử bằng QEMU với 1.436 lần suy luận, gồm 4 lượt × 359 thiết bị, 2026-11-17: RSS tăng trong khoảng 280 thiết bị đầu, sau đó
đứng yên tới hết, kể cả với thiết bị mới. Xem phần nào đang tăng:
`grep -E 'VmRSS|RssAnon|RssFile|RssShmem' /proc/$(pidof sdc_agent)/status`. `RssAnon` là heap, `RssFile`/`RssShmem` là file
model.

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
| `deploy_model.py` | Một lệnh từ model mới tới `build/router/`, và chép lên router |
| `model_origin/` | Các bản model gốc (`<run>/release/sdc_os.onnx`, contract, manifest) |
| `agent/` | Mã C++ (`sdc_agent`, `sdc_infer`, `feature_extract`, `hostname_engine`) và các script chạy trên router |
| `build/router/` | Bộ file chép lên router |
| `build/ort/` | Model `.ort`, `sdc_hn.bin`, bộ test `parity_cases.txt` |
| `build/test/` | pcap thử, kết quả mong đợi, `parity_inputs.txt` (bộ input cố định để sinh bộ test cho mọi model) |
| `model_split/` | Script Python tách model, tạo bộ test, tạo pcap thử, kiểm tra log observation (`check_observations.py`) |
| `toolchain/` | Script build, chạy trong WSL |

## Build lại (WSL)

Đổi model thì dùng `deploy_model.py` (ở trên). Phần dưới chỉ cần khi sửa mã C++ hoặc cài lại máy.
Toolchain, mã nguồn ONNX Runtime và QEMU nằm ở `~/sdc-router`.

```bash
cd /mnt/d/01.AI_Security/Router_X740_C/04.Test_model_SDC_Router/toolchain
bash setup_toolchain.sh aarch64                                  # toolchain musl của Bootlin
bash fetch_ort.sh                                                # mã nguồn ONNX Runtime 1.28.0
bash build_ort_arm64.sh ../build/ort/required_operators.config   # ORT rút gọn, link tĩnh
bash build_agent.sh                                              # tạo build/sdc_infer, build/sdc_agent
bash fetch_qemu.sh                                               # qemu-aarch64 để chạy thử trên PC
bash test_agent.sh ../build/test/obs.pcap ../build/test/agent.jsonl
bash package_router.sh                                           # gom vào build/router, tạo checksum
```

Các bước tải và build ORT chỉ cần chạy một lần. Nếu chỉ sửa mã agent thì chạy `bash build_router.sh`
(link agent, đối chiếu trên QEMU bằng `test_parity.sh`, chạy pcap thử, đóng gói).

## Khác với model gốc

- `sdc_os.onnx` được tách bằng `model_split/split_model.py` thành `sdc_packet` (phần trước nhánh hostname) và
  `sdc_tail` (phần sau). Nhánh hostname được viết lại bằng C++ (`hostname_engine.cpp`, dữ liệu trong `sdc_hn.bin`)
  để chạy được với bản ONNX Runtime rút gọn.
- Độ khớp với model gốc được kiểm bằng `sdc_infer` trên `parity_1000.txt` (bước 2).
- Từ bản `20261116_094850_release`, trọng số nhánh hostname trong graph được nén 4 bit (`weight4_*`, giải mã
  `(q - 8) * scale`). `export_hostname.py` giải nén về int8 nên `sdc_hn.bin` và mã C++ giữ nguyên định dạng.
  Luật, mask và bảng `implied` của nhánh hostname nằm trong `sdc_os_contract.json` cạnh model (không còn nhúng
  trong metadata), `export_hostname.py` đọc file này và kiểm sha256.
- tcpdump chỉ bắt gói TLS ra cổng 443 nếu là gói mở đầu handshake hoặc có cờ PSH, để đỡ tốn CPU khi tải nhiều.
