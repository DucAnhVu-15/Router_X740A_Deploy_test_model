# Tool test brute-force SSH cho model IDS

Sinh traffic brute-force SSH để model IDS ở `05.Test_model_IDS` phát hiện. Chỉ dùng trong lab, với
thiết bị bạn được phép test. Mục tiêu là tạo đúng *mẫu lưu lượng*, không nhằm bẻ khoá: wordlist mặc
định là mật khẩu giả (`pass1`..`pass400`), và tool tự dừng nếu lỡ trúng.

## Chuẩn bị (một lần)

```bat
python -m pip install paramiko
```

## Các bước test

### 1. Tìm máy mở SSH (cmd trên PC)

```bat
nmap -Pn -n -p 22 192.168.1.182 192.168.1.27 192.168.1.254
```

Chọn máy báo `22/tcp open`. **Không** nhắm router `192.168.1.1` (bạn đang SSH vào nó).

### 2. Bật model trên router

Cửa sổ router:

```sh
cd /tmp/ids && sh run_ids.sh
```

### 3. Chạy brute-force (cmd trên PC)

```bat
cd /d D:\01.AI_Security\Router_X740_A\Tool_BruteForce_test
python ssh_bruteforce.py <IP_MỤC_TIÊU> --intensity medium --max 1000
```

Trên router kỳ vọng thấy `attack_start` với `"host":"192.168.1.186"` và `"class":"bruteforce"`.

## Mức cường độ

| `--intensity` | Luồng | Tốc độ | Dùng khi |
|---|---|---|---|
| `stealth` | 1 | 1 lần/giây | thử brute-force chậm, khó phát hiện |
| `low` | 2 | 5 lần/giây | |
| `medium` | 4 | 20 lần/giây | mặc định, giống hydra `-t 4` |
| `aggressive` | 16 | không giới hạn | thử tải nặng |

Ép tay: `--rate 10` (lần/giây), `--threads 8`.

## Tham số hay dùng

| Tham số | Ý nghĩa |
|---|---|
| `--max N` | số lần thử tối đa (mặc định 1000) |
| `-U file` / `-P file` | wordlist user / mật khẩu riêng |
| `--port N` | cổng SSH khác 22 |
| `--allow-public` | cho phép đích ngoài dải IP riêng (mặc định chặn) |

## Brute-force Telnet (camera, thiết bị IoT cổng 23)

Camera `.27` mở cổng 23. `telnet_bruteforce.py` sinh mẫu brute-force telnet. Dùng khi mục tiêu không
có SSH. Cùng tham số với `ssh_bruteforce.py`.

```bat
cd /d D:\01.AI_Security\Router_X740_A\Tool_BruteForce_test
python telnet_bruteforce.py 192.168.1.27 --intensity aggressive --max 1000
```

Kỳ vọng router báo `attack_start` với `"host":"192.168.1.186"`, lớp `bruteforce` (hoặc `recon` nếu
tốc độ thấp — như SSH, brute-force chậm hay bị đọc nhầm hoặc trượt).

Lưu ý: camera có thể giới hạn số kết nối telnet đồng thời; nếu nhiều "bi tu choi" thì giảm `--intensity`.

## Test DoS (lớp `dos`)

**Cảnh báo:** flood có thể làm camera/thiết bị IoT treo hoặc khởi động lại. Chỉ nhắm thiết bị bạn
được phép test. Bắt đầu tốc độ vừa, thời gian ngắn, dừng ngay nếu thiết bị đơ.

### UDP flood — cách chính (nhanh, không cần admin)

```bat
cd /d D:\01.AI_Security\Router_X740_A\Tool_BruteForce_test
python dos_flood.py 192.168.1.27 --type udp --port 53 --rate 8000 --duration 12
```

Socket thường đạt vài chục nghìn gói/giây, đủ cao để model gắn `dos`. Kỳ vọng `attack_start` với
`"host":"192.168.1.186"` và `"class":"dos"`.

### SYN/ACK/FIN/RST/ICMP flood

`dos_flood.py --type syn` dựng gói thô bằng scapy, **cần cmd "Run as administrator"**. Nhưng scapy
trên Windows bắn chậm (vài chục gói/giây), thường không đủ nhanh để ra `dos` — nó sẽ bị đọc thành
`bruteforce`. Muốn SYN flood tốc độ cao, dùng **hping3 trong WSL**:

```bat
wsl -d Ubuntu -- bash -lc "sudo apt-get install -y hping3; sudo hping3 -S -p 80 --flood 192.168.1.27"
```

Lưu ý: hping3 trong WSL có thể bị NAT đổi IP nguồn; kiểm tra trên router xem gói mang IP nào trước
khi tin kết quả.

| Tham số | Ý nghĩa |
|---|---|
| `--type` | udp (nhanh) / syn / ack / fin / rst / icmp (scapy, chậm) |
| `--rate` | gói mỗi giây mục tiêu (mặc định 8000) |
| `--duration` | số giây (mặc định 12) |
| `--port` | cổng đích |
| `--src` | IP nguồn cho scapy, mặc định 192.168.1.186 |

## Lấy kết quả model về xem

```bat
cd /d D:\01.AI_Security\Router_X740_A\05.Test_model_IDS
scp -O admin@192.168.1.1:/tmp/ids_windows.csv build\
python tools\summarize_run.py build\ids_windows.csv
```

## Lưu ý

- Nếu tool báo nhiều "bị từ chối": host không mở SSH, chặn, hoặc đang giới hạn kết nối. Kiểm tra lại
  đích và cổng ở bước 1.
- Nếu router không thấy gói mang IP `.186`: hiếm, nhưng khi đó báo lại để kiểm tra đường đi của traffic.
- Đổi `--intensity` rồi chạy lại để so tỉ lệ phát hiện giữa brute-force chậm và nhanh. Giữa các lần,
  chờ router in `attack_end` để hai đợt không bị gộp.
