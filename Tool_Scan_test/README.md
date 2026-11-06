# Tool test quét (recon) cho model IDS

Sinh traffic recon cho model IDS phát hiện. Chạy trong lab, nhắm thiết bị bạn được phép test.
Máy tấn công: `192.168.1.186`. Mục tiêu một máy: camera `192.168.1.27`. Quét cả dải: `192.168.1.0/24`.

Hai lựa chọn: `net_scan.py` (Python, không cần nmap/admin) hoặc `nmap`. Cột "lớp kỳ vọng" lấy từ kết
quả test của run `20261105_1550`.

---

## Cách 1: net_scan.py (khuyên dùng — không cần cài gì)

Quét TCP connect bằng Python, nguồn ép về `.186`. Hai pha: dò host sống rồi quét cổng.

```bat
cd /d D:\01.AI_Security\Router_X740_A\Tool_Scan_test
```

| Việc | Lệnh |
|---|---|
| Dò host bằng **ARP** (thấy hết, như router) | `python net_scan.py 192.168.1.0/24 --arp --discover-only` |
| Dò host bằng TCP (nhanh, sót máy firewall) | `python net_scan.py 192.168.1.0/24 --discover-only` |
| Quét cổng 1-1024 các host sống | `python net_scan.py 192.168.1.0/24 --arp` |
| Quét **toàn bộ 65535 cổng** mọi IP | `python net_scan.py 192.168.1.0/24 --skip-discover --ports all` |
| Quét một máy, mọi cổng | `python net_scan.py 192.168.1.27 --ports 1-65535` |
| Quét nhanh cổng hay gặp | `python net_scan.py 192.168.1.0/24 --arp --ports top` |

| Tham số | Ý nghĩa |
|---|---|
| `--ports` | `1-1024` / `all` / `top` / `22,80,443` |
| `--arp` | dò host bằng ARP — thấy cả máy bật firewall. **Cần cmd "Run as administrator"** |
| `--skip-discover` | bỏ pha dò, quét cổng thẳng mọi IP trong dải |
| `--discover-only` | chỉ tìm host sống, không quét cổng |
| `--threads` | số luồng (mặc định 400) |
| `--timeout` | giây chờ mỗi cổng (mặc định 0.5) |
| `--src` | IP nguồn, mặc định 192.168.1.186 |

Lưu ý:
- Dò bằng TCP (`--discover-only` không kèm `--arp`) chỉ thử 15 cổng phổ biến, nên máy không mở cổng
  nào (điện thoại, máy firewall) sẽ bị sót. Dùng `--arp` để thấy mọi thiết bị như bảng của router.
- `--arp` cần quyền admin (Npcap gửi gói ARP thô). ARP sweep cũng là traffic recon, model báo `recon`.
- `--ports all` cả dải rất chậm (254 × 65535 kết nối) và tạo traffic rất nặng.

---

## Cách 2: nmap

## Chuẩn bị

Cài nmap kèm Npcap:

```bat
winget install -e --id Insecure.Nmap
```

Mở cmd **mới** sau khi cài. Nếu gõ `nmap` báo không nhận lệnh, dùng đường dẫn đầy đủ
`"C:\Program Files (x86)\Nmap\nmap.exe"` thay cho `nmap`.

Các loại quét `-sS -sF -sN -sX -sA -sU` cần **cmd "Run as administrator"** (gửi gói thô qua Npcap).
Riêng `-sT` (connect scan) chạy bằng cmd thường.

Trước khi quét, bật model trên router: `cd /tmp/ids && sh run_ids.sh`.

> **Đường dẫn nmap:** nếu gõ `nmap` báo "not recognized", thay `nmap` bằng
> `"C:\Program Files (x86)\Nmap\nmap.exe"` trong mọi lệnh dưới (hoặc mở cmd mới sau khi cài).
> Các loại cần gói thô (`-sS -sF -sN -sX -sA -sU`) phải mở **cmd Run as administrator**.

## 4 loại chính

| Loại | Lệnh | Admin? | Lớp kỳ vọng |
|---|---|:--:|---|
| **TCP SYN Scan** | `nmap -Pn -n -sS --top-ports 1000 -T4 192.168.1.27` | có | recon |
| **TCP Connect Scan** | `nmap -Pn -n -sT --top-ports 1000 192.168.1.27` | không | recon |
| **UDP Port Scan** | `nmap -Pn -n -sU --top-ports 100 192.168.1.27` | có | recon (~87% task) |
| **ICMP Ping Sweep** | `nmap -sn -PE -n 192.168.1.0/24` | không | **không bắt** (giới hạn model, 0/118 task) |

TCP Connect Scan chạy được không cần nmap/admin: `python net_scan.py 192.168.1.27 --ports 1-1024`.

## Quét cổng (một máy) — các loại khác

| Loại | Lệnh | Admin? | Lớp kỳ vọng |
|---|---|:--:|---|
| FIN scan | `nmap -Pn -n -sF --top-ports 200 192.168.1.27` | có | recon |
| NULL scan | `nmap -Pn -n -sN --top-ports 200 192.168.1.27` | có | recon |
| XMAS scan | `nmap -Pn -n -sX --top-ports 200 192.168.1.27` | có | recon |
| ACK scan (dò firewall) | `nmap -Pn -n -sA --top-ports 200 192.168.1.27` | có | recon |

`-Pn` bỏ bước ping (quét cả khi mục tiêu chặn ping). `-n` không phân giải DNS. `-T4` quét nhanh.

## Quét IP / dò host (cả dải)

| Loại | Lệnh | Admin? | Lớp kỳ vọng |
|---|---|:--:|---|
| ARP scan | `nmap -Pn -n -sn -PR 192.168.1.0/24` | có | recon |
| TCP SYN host discovery | `nmap -n -sn -PS22,80,443 192.168.1.0/24` | có | recon (~83% task) |
| TCP ACK host discovery | `nmap -n -sn -PA80 192.168.1.0/24` | có | recon (~91% task) |
| **Ping sweep (ICMP)** | `nmap -n -sn -PE 192.168.1.0/24` | không | **TRƯỢT: model không bắt (0/118 task)** |

Ping sweep không bị phát hiện là **giới hạn của model**, không phải lỗi. ICMP echo tới nhiều đích
quá giống traffic bình thường.

## Xem kết quả

Trên router, mỗi đợt quét sinh `attack_start`/`attack_end` với `"host":"192.168.1.186"`:

```sh
grep attack_end /tmp/ids_alerts.jsonl | grep 192.168.1.186
```

Giữa các lần quét, đợi router in `attack_end` để hai đợt không bị gộp (khoảng cách > 60 giây).

Lấy chi tiết cửa sổ về PC:

```bat
cd /d D:\01.AI_Security\Router_X740_A\05.Test_model_IDS
scp -O admin@192.168.1.1:/tmp/ids_windows.csv build\
python tools\summarize_run.py build\ids_windows.csv
```

## Lưu ý

- **Tắt bớt app nền trên máy tấn công `.186`** (trình duyệt, đồng bộ cloud) trước khi test. Traffic
  TLS nền tốc độ cao làm pha loãng tín hiệu quét/tấn công, khiến model dễ bỏ sót — đã gặp khi test DoS.
- Giữa mỗi lần quét, **đợi `attack_end`** của `.186` (cách nhau > 60 giây) để hai đợt không bị gộp.
- Camera `.27` ngủ thì quét có thể không ra kết quả; ping một cái cho dậy rồi quét lại.
- Scan tốc độ rất cao đôi khi bị gắn `dos` thay vì `recon` — vẫn có báo động.
- Máy mục tiêu của một trận quét đôi khi cũng bị báo động, vì nó bắn trả RST/SYN-ACK hàng loạt.
