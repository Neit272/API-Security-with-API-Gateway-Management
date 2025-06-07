## Cấu hình HTTP Event Collector (HEC) trên Splunk (UI)
1. Đăng nhập vào Splunk Web.
2. Đi đến Settings > Data Inputs.
3. Nhấp vào HTTP Event Collector trong mục "Local inputs" hoặc "Forwarded inputs".
4. Global Settings (Cài đặt chung):
- Ở góc trên bên phải, nhấp vào Global Settings.
- Đảm bảo All Tokens được đặt thành Enabled.
- Ghi lại HTTP Port Number (mặc định là 8088).
- Tắt SSL.
- Nhấp Save.
5. Tạo Token mới:
- Quay lại trang HTTP Event Collector, nhấp vào New Token ở góc trên bên phải.
- Name: (ví dụ: kong_api_logs).
- (Tùy chọn) Description.
- (Tùy chọn) Source name override: có thể để trống.
- Output Group: Thường để mặc định.
- Nhấp Next.
- Select Source Type:
    - Nhấp vào Select.
    - Tìm kiếm và chọn _json.
- Default Index: Chọn index muốn lưu trữ log này (main).
- Allowed Indexes: Đảm bảo index bạn chọn ở trên được liệt kê và chọn ở đây.
- Nhấp Review.
- Xem lại cấu hình và nhấp Submit.
6. Sao chép Token Value:
- Sau khi tạo thành công, Splunk sẽ hiển thị Token Value, paste vào .env.
