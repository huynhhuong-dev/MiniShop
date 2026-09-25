# Bảng yêu cầu an toàn (security requirements) của MiniShop, tuần 2

Họ tên: Nguyễn Đoàn Huỳnh Hương

MSSV:2305CT0721

Sửa tệp này ngay trên trình duyệt: bấm biểu tượng cây bút (**Edit this file**), gõ vào giữa hai dấu `|`, rồi bấm **Commit changes**. Mỗi hàng của bảng phải nằm trên đúng một dòng. Gõ vài hàng thì bấm **Commit changes** một lần, để không mất bài nếu lỡ đóng trang.

## 1. Mười hai yêu cầu (tầng L2, Mục 5 của tài liệu thực hành buổi 2)

Hàng YC-10 là hàng mẫu, chép từ Mục 5.3 của tài liệu thực hành buổi 2 và điền sẵn để đối chiếu. Giữ nguyên hàng ấy; mười một hàng còn lại là bài của sinh viên.

| Mã | Phát biểu | Điều kiện nghiệm thu (acceptance condition) | Cách kiểm chứng (verification) | Vị trí trong mã nguồn |
|---|---|---|---|---|
| YC-01 |Mật khẩu tài khoản phải được lưu dưới dạng hash bảo mật  | CSDL không lưu mật khẩu ở dạng plain-text |Kiểm tra bảng `users` trong `minishop.db`, trường `password_md5` lưu chuỗi hash | `db.py`, hàm `find_login` |
| YC-02 | Hệ thống phải chống tấn công SQL Injection ở chức năng đăng nhập | Tham số đầu vào được xử lý an toàn, không thể chèn câu lệnh SQL | Nhập `' OR '1'='1` vào ô đăng nhập; hệ thống báo lỗi hoặc không cho đăng nhập thành công | `db.py`, hàm `find_login` |
| YC-03 | Hệ thống phải chống tấn công SQL Injection ở chức năng tìm kiếm | Từ khóa tìm kiếm không làm thay đổi cấu trúc câu truy vấn SQL | Nhập `'; DROP TABLE products; --` vào ô tìm kiếm; CSDL không bị mất bảng | `db.py`, hàm `search_products` |
| YC-04 | Dữ liệu đầu ra phải được escape để chống tấn công XSS | Các thẻ HTML/Script nhập vào phải hiển thị dưới dạng văn bản thuần | Tạo sản phẩm có tên `<script>alert(1)</script>`; trình duyệt không bật hộp thoại alert | `views.py` / Khung mẫu HTML |
| YC-05 | Ứng dụng phải xác thực người dùng trước khi cho phép vào trang quản trị | Người dùng chưa đăng nhập không thể truy cập các đường dẫn bảo mật | Truy cập trực tiếp đường dẫn quản trị khi chưa đăng nhập; hệ thống chuyển hướng về trang `/login` | `app.py` / `views.py` |
| YC-06 | Phiên đăng nhập (Session) phải được bảo mật bằng Secret Key đủ mạnh | Secret key không dùng giá trị mặc định dễ đoán | Kiểm tra biến `secret_key` trong cấu hình ứng dụng Flask | `app.py`, dòng `app.secret_key` |
| YC-07 | Không hiển thị thông tin lỗi chi tiết (StackTrace) cho người dùng cuối | Khi xảy ra lỗi 500, giao diện chỉ hiện thông báo lỗi chung chung | Truy cập đường dẫn gây lỗi; trang web không để lộ cấu trúc thư mục hay dòng code lỗi | `app.py` |
| YC-08 | Giá sản phẩm và số lượng tồn kho không được chấp nhận giá trị âm | Hệ thống từ chối cập nhật/thêm mới sản phẩm có giá hoặc số lượng `< 0` | Thêm sản phẩm với giá `-50000`; ứng dụng báo lỗi không hợp lệ | `views.py` / `db.py` |
| YC-09 | Các tệp nhạy cảm (như `minishop.db`) không được đưa lên kho Git | Tệp cơ sở dữ liệu nằm trong danh sách loại trừ | Kiểm tra tệp `.gitignore` chứa `minishop.db` và không có tệp `.db` trên repository GitHub | `.gitignore` |
| YC-10 (hàng mẫu, điền sẵn) | Máy chủ MiniShop không được phục vụ yêu cầu đến từ máy khác trong mạng phòng máy | Ứng dụng chỉ lắng nghe trên địa chỉ vòng lặp nội bộ, không lắng nghe trên địa chỉ mà máy khác gọi tới được | Chạy MiniShop, rồi từ máy bên cạnh mở địa chỉ IP của máy này kèm cổng 8000; trình duyệt máy bên cạnh phải báo không kết nối được | `app.py`, dòng `HOST = "127.0.0.1"` |
| YC-11 | Giới hạn độ dài từ khóa tìm kiếm để tránh tấn công từ chối dịch vụ (DoS) | Chuỗi tìm kiếm quá dài sẽ bị cắt gọn hoặc từ chối | Nhập chuỗi 10.000 ký tự vào ô tìm kiếm; hệ thống không bị treo hoặc ngốn RAM | `views.py` |
| YC-12 | Chỉ cho phép các phương thức HTTP hợp lệ trên từng route | Route đăng nhập chỉ nhận phương thức POST cho dữ liệu xác thực | Gửi yêu cầu GET chứa mật khẩu lên route xử lý đăng nhập; ứng dụng từ chối | `app.py` / `views.py` |

## 2. Hai tiêu chí chấp nhận (acceptance criteria), tầng L3 phần a

### Tiêu chí thứ nhất, cho yêu cầu YC-__ (ghi mã đã chọn, thí dụ YC-07)

- Đầu vào: Nhập chuỗi `' OR '1'='1` vào ô tài khoản và mật khẩu bất kỳ trên trang `/login`.
- Kết quả quan sát được phải là: Trang web hiển thị thông báo "Tên đăng nhập hoặc mật khẩu không đúng" và không cho phép đăng nhập.
- Kết quả chứng tỏ chưa đạt: Hệ thống đăng nhập thành công vào tài khoản đầu tiên mà không cần mật khẩu đúng.

### Tiêu chí thứ hai, cho yêu cầu YC-__ (ghi mã đã chọn)

- Đầu vào: Nhập từ khóa `'; DROP TABLE products; --` vào ô tìm kiếm sản phẩm.
- Kết quả quan sát được phải là:Trang web trả về thông báo không tìm thấy sản phẩm, bảng `products` trong CSDL vẫn hoạt động bình thường.
- Kết quả chứng tỏ chưa đạt:Ứng dụng báo lỗi kết nối CSDL hoặc bảng `products` bị xóa.

## 3. Yêu cầu thứ mười ba, tầng L3 phần b

| Mã | Phát biểu | Điều kiện nghiệm thu | Cách kiểm chứng |
|---|---|---|---|
| YC-13 |Tự động đăng xuất phiên làm việc (Session Timeout) khi người dùng không thao tác sau một khoảng thời gian | Sau 15 phút không có thao tác, phiên làm việc tự động hủy | Đăng nhập, giữ nguyên trang 15 phút không bấm gì, sau đó bấm làm mới trang; hệ thống yêu cầu đăng nhập lại |

Vì sao MiniShop cần yêu cầu này: Giúp bảo vệ tài khoản người dùng/quản trị viên khỏi bị truy cập trái phép nếu họ quên đăng xuất khi rời khỏi máy tính ở nơi công cộng hoặc phòng máy thực hành.

Điều gì xảy ra nếu thiếu nó: Nếu thiếu tính năng này, phiên làm việc (session) của người dùng/quản trị viên sẽ tồn tại vô thời hạn trên trình duyệt. Nếu người dùng quên đăng xuất khi rời khỏi máy tính tại phòng máy thực hành hoặc nơi công cộng, kẻ gian có thể trực tiếp sử dụng trình duyệt đó để truy cập trang quản trị, sửa/xóa dữ liệu sản phẩm hoặc đánh cắp thông tin hệ thống mà không cần nhập lại mật khẩu.
