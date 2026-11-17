# Capture lưu lượng trên router VNPT IPQ5332

Kiểm tra trực tiếp ngày 13/11/2026. Router OpenWrt SNAPSHOT, kernel 6.6.47; driver Qualcomm QSDK. Không sửa script gốc, không lưu thay đổi UCI, không restart Wi-Fi. Thử nghiệm tạm thời đã được khôi phục.

## Kết quả đã xác nhận

- Laptop 192.168.1.49, .78, .93 cùng ath0 (2,4 GHz). Orange Pi .15 thuộc ath1 (5 GHz).
- Mặc định: ap_bridge=1, hairpin_mode=0 trên ath0, ath1, ath2.
- Mặc định: .49 ping .78 thành công 3/3 nhưng tcpdump -i any trên router không thấy ICMP.
- Thử ath0 ap_bridge=0, hairpin_mode=1: .49 ping .78 thành công 3/3; router thấy đủ request/reply trên br-lan. .49 ping .15 cũng thành công 3/3 và thấy đủ hai chiều.
- Kết quả xác nhận đường chuyển tiếp nội bộ Wi-Fi là nguyên nhân che khuất ICMP cùng BSS. Chưa kiểm chứng tính đầy đủ của TCP/UDP khi được tăng tốc hoặc lưu lượng tải cao.

## Bật để capture giữa các laptop: đã kiểm chứng trên ath0

Chạy trên router:

```sh
echo 1 > /sys/class/net/ath0/brport/hairpin_mode
cfg80211tool ath0 ap_bridge 0
```

Hairpin cho phép bridge gửi frame trở lại cổng đã nhận. Cần bật hairpin cùng với tắt ap_bridge; chỉ tắt ap_bridge có thể làm các client cùng Wi-Fi mất liên lạc.

Trong Wireshark SSHdump, dùng custom remote capture command:

```sh
/usr/bin/tcpdump -i br-lan -nn -U -s 0 -B 8192 -w - 'not (host 192.168.1.49 and tcp port 22)'
```

Không thêm filter `ip or arp` nếu muốn giữ IPv6 và các EtherType khác. Xóa display filter của Wireshark khi muốn xem mọi gói đã capture. Với custom command, đặt biểu thức ngay trong command như trên, để tránh phụ thuộc việc SSHdump có áp dụng ô Remote capture filter hay không. Ngoại lệ SSH trên đây chủ động bỏ lưu lượng TCP/22 của laptop .49, gồm luồng vận chuyển capture, để tránh capture tự khuếch đại.

Lệnh capture cũ trên router dùng `-s 128` và `ip or arp`: giới hạn 128 byte mỗi gói, chỉ giữ IPv4/ARP.

Hoàn nguyên ath0 sau khi bắt xong:

```sh
cfg80211tool ath0 ap_bridge 1
echo 0 > /sys/class/net/ath0/brport/hairpin_mode
```

## Áp dụng cùng nguyên lý cho các AP còn lại

Lệnh sau mở rộng cấu hình đã thử trên ath0 sang ath1 và ath2. Hai interface sau chưa được thử bằng cặp client cùng BSS:

```sh
for capture_if in ath0 ath1 ath2; do
    echo 1 > /sys/class/net/$capture_if/brport/hairpin_mode
    cfg80211tool "$capture_if" ap_bridge 0
done
```

Khôi phục về trạng thái đã đọc trên router:

```sh
for capture_if in ath0 ath1 ath2; do
    cfg80211tool "$capture_if" ap_bridge 1
    echo 0 > /sys/class/net/$capture_if/brport/hairpin_mode
done
```

Đây là cấu hình runtime; Wi-Fi reload hoặc reboot có thể đặt lại. Đường chuyển tiếp qua CPU có thể giảm thông lượng. Không thay đổi cấu hình guest/client isolation trên các SSID khác theo mẫu này nếu không có mục đích cho phép chúng liên lạc.

## TCP/UDP tăng tốc: cần xử lý thêm nếu bị thiếu gói

Router có ECM, PPE, SFE và driver Wi-Fi Qualcomm. Chỉ bật hairpin chưa đủ chứng minh toàn bộ TCP/UDP đi qua tcpdump. Các file điều khiển sau tồn tại và hiện đều bằng 0:

```text
/sys/kernel/debug/ecm/front_end_ipv4_stop
/sys/kernel/debug/ecm/front_end_ipv6_stop
```

Một phương án debug là dừng ECM frontend, loại các bản ghi acceleration cũ và tạo lại traffic. Mẫu dưới đây có trong mã nguồn NSS client, nhưng CHƯA được chạy/thử trên router này:

```sh
echo 1 > /sys/kernel/debug/ecm/front_end_ipv4_stop
echo 1 > /sys/kernel/debug/ecm/front_end_ipv6_stop
echo 1 > /sys/kernel/debug/ecm/ecm_db/defunct_all
```

Đây là xóa trạng thái acceleration ECM, không phải đề nghị xóa conntrack của firewall. Có thể ảnh hưởng hiệu năng hoặc traffic đang chạy; chỉ dùng trong phiên debug. Không đảm bảo dừng mọi đường chuyển tiếp phần cứng ngoài ECM.

Khôi phục hai frontend về giá trị đã đọc:

```sh
echo 0 > /sys/kernel/debug/ecm/front_end_ipv4_stop
echo 0 > /sys/kernel/debug/ecm/front_end_ipv6_stop
```

Kiểm chứng bằng cùng một phiên TCP/UDP kéo dài: capture ở cả endpoint và router, đối chiếu payload/sequence và số byte, kiểm tra tcpdump dropped-by-kernel. Với -i any, một gói có thể xuất hiện nhiều lần ở các interface; không so tổng số dòng thô. Không tuyên bố capture đầy đủ chỉ dựa vào ping.

## enable_all_port.sh và PPE mirror

Đã đọc bản trong /root/scripts trên router và bản tại /home/linova/Documents/demo_t5/scripts: các bước tạo group=dev1, tạo rule mirror và map ACL sang group đều bị comment.

Trạng thái đọc trực tiếp:

```text
mirror analyzer port: 0
capture_core core_id=3
Mirror groups Active Count = 0
mirror_acl_active_mapping_count = 0
```

Do đó script chỉ chuẩn bị một phần hệ thống mirror, chưa tạo đường nhận gói đầy đủ. Việc tắt ecm_classifier_emesh và sawf_enabled không đồng nghĩa tắt toàn bộ acceleration. Không nên đơn giản bỏ comment mọi dòng: cần xác nhận cú pháp, ACL ID chưa dùng, phạm vi rule và đường Wi-Fi có thực sự đi qua PPE. PPE mirror cũng không tự đảm bảo nhìn thấy frame được chuyển tiếp nội bộ trong Wi-Fi trước PPE. Trong lần kiểm tra này không thêm/xóa ACL và không nạp/gỡ module.

## “Tất cả gói” có ba phạm vi khác nhau

1. Traffic LAN/IP giữa client: hairpin + ap_bridge là giải pháp đã xác nhận cho ICMP cùng ath0; cần xử lý/kiểm chứng acceleration cho TCP/UDP.
2. Traffic trên các interface WAN/VLAN khác: br-lan không đại diện mọi interface; dùng any hoặc nhiều capture riêng, vẫn phải tính đường offload và bản sao trùng.
3. Khung vô tuyến 802.11 như beacon, ACK, retry: cần monitor capture, không thu được đầy đủ từ br-lan. Router có công cụ lite_mon, nhưng chưa cấu hình/thử. Cần cấu hình theo đúng driver/firmware, bắt từng radio/kênh; adapter monitor độc lập là một lựa chọn để tránh thay đổi AP đang phục vụ. Monitor capture không đảm bảo thu đủ mọi khung và data có thể còn mã hóa.

## Nguồn đối chiếu

- Linux bridge, hairpin: https://docs.kernel.org/networking/bridge.html
- Mẫu điều khiển ECM trong NSS client: https://github.com/robimarko/nss-packages/blob/main/qca/qca-nss-clients/files/qca-nss-ipsec

Các kết luận riêng cho router dựa trên đọc cấu hình và phép thử trực tiếp nêu trên. Tài liệu IPQ95xx SoC Software User Guide trong thư mục demo_t5 chủ yếu mô tả nền tảng/boot, không cung cấp quy trình capture Wi-Fi đầy đủ cho thiết bị này.
