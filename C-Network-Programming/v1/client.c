#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>

#define BUFFER_SIZE 16384  // Tăng buffer size để cải thiện hiệu suất
#define UPDATE_INTERVAL (100 * 1024)  // Cập nhật tiến trình sau mỗi 100 KB

// Hàm định dạng kích thước tệp thành dạng dễ đọc
char* format_size(long size, char* buf, size_t buf_size) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double file_size = size;

    while (file_size >= 1024 && unit < 4) {
        file_size /= 1024;
        unit++;
    }

    snprintf(buf, buf_size, "%.2f %s", file_size, units[unit]);
    return buf;
}

// Hàm sao chép tệp với thông tin chi tiết
void copy_file(ssh_session session, const char* source_path, const char* dest_path) {
    struct stat file_stat;
    FILE *source_file;
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    sftp_session sftp;
    sftp_file dest_file;
    long file_size;
    long total_bytes = 0;
    long last_update_bytes = 0;
    time_t start_time, current_time, end_time;
    double elapsed_time, time_taken;

    // Kiểm tra thông tin tệp nguồn
    if (stat(source_path, &file_stat) < 0) {
        printf("Error: Cannot stat file %s\n", source_path);
        return;
    }
    file_size = file_stat.st_size;

    // Mở tệp nguồn
    source_file = fopen(source_path, "rb");
    if (!source_file) {
        printf("Error: Cannot open source file %s\n", source_path);
        return;
    }

    // Khởi tạo phiên SFTP
    sftp = sftp_new(session);
    if (sftp == NULL) {
        printf("Error: SFTP initialization failed\n");
        fclose(source_file);
        return;
    }

    if (sftp_init(sftp) != SSH_OK) {
        printf("Error: SFTP session init failed: %s\n", ssh_get_error(session));
        fclose(source_file);
        sftp_free(sftp);
        return;
    }

    // Mở tệp đích trên server
    dest_file = sftp_open(sftp, dest_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (dest_file == NULL) {
        printf("Error: Cannot open destination file %s: %s\n", dest_path, ssh_get_error(session));
        fclose(source_file);
        sftp_free(sftp);
        return;
    }

    // Hiển thị thông báo bắt đầu sao chép
    char file_size_str[20];
    format_size(file_size, file_size_str, sizeof(file_size_str));
    printf("Copying %s (%s)...\n", source_path, file_size_str);

    // Bắt đầu đo thời gian
    start_time = time(NULL);

    // Vòng lặp sao chép tệp
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, source_file)) > 0) {
        if (sftp_write(dest_file, buffer, bytes_read) != bytes_read) {
            printf("\nError: Write failed: %s\n", ssh_get_error(session));
            break;
        }

        total_bytes += bytes_read;

        // Cập nhật tiến trình sau mỗi UPDATE_INTERVAL hoặc khi hoàn tất
        if (total_bytes - last_update_bytes >= UPDATE_INTERVAL || total_bytes == file_size) {
            double percentage = (total_bytes * 100.0) / file_size;
            current_time = time(NULL);
            elapsed_time = difftime(current_time, start_time);

            char total_str[20], speed_str[20];
            format_size(total_bytes, total_str, sizeof(total_str));

            if (elapsed_time > 0) {
                double speed = total_bytes / elapsed_time;
                format_size(speed, speed_str, sizeof(speed_str));
                printf("\rProgress: %.1f%% (%s / %s) - %s/s - %.1f seconds",
                       percentage, total_str, file_size_str, speed_str, elapsed_time);
            } else {
                printf("\rProgress: %.1f%% (%s / %s) - N/A - %.1f seconds",
                       percentage, total_str, file_size_str, elapsed_time);
            }
            fflush(stdout); // Đảm bảo xuất ra ngay lập tức
            last_update_bytes = total_bytes;
        }
    }

    // Kết thúc đo thời gian và hiển thị thông báo hoàn tất
    end_time = time(NULL);
    time_taken = difftime(end_time, start_time);

    if (time_taken > 0) {
        double avg_speed = file_size / time_taken;
        char avg_speed_str[20];
        format_size(avg_speed, avg_speed_str, sizeof(avg_speed_str));
        printf("\nCompleted: %s - Size: %s - Time: %.2f seconds - Avg. Speed: %s/s\n",
               source_path, file_size_str, time_taken, avg_speed_str);
    } else {
        printf("\nCompleted: %s - Size: %s - Time: %.2f seconds\n",
               source_path, file_size_str, time_taken);
    }

    // Giải phóng tài nguyên
    fclose(source_file);
    sftp_close(dest_file);
    sftp_free(sftp);
}

// Hàm chính
int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <user> <host> <port> <source_dir> <dest_dir>\n", argv[0]);
        return 1;
    }

    ssh_session session;
    int rc;
    DIR *dir;
    struct dirent *entry;

    // Khởi tạo phiên SSH
    session = ssh_new();
    if (session == NULL) {
        printf("Error: Failed to create SSH session\n");
        return 1;
    }

    // Thiết lập các tùy chọn SSH
    ssh_options_set(session, SSH_OPTIONS_HOST, argv[2]);
    ssh_options_set(session, SSH_OPTIONS_USER, argv[1]);
    ssh_options_set(session, SSH_OPTIONS_PORT_STR, argv[3]);
    // Hỗ trợ nhiều thuật toán host key
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256");
    // Tắt kiểm tra known_hosts
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");

    // Thông báo kết nối
    printf("Connecting to %s@%s:%s...\n", argv[1], argv[2], argv[3]);
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        printf("Error: Connection failed: %s\n", ssh_get_error(session));
        ssh_free(session);
        return 1;
    }
    printf("Connection established\n");

    // Xác thực bằng khóa công khai
    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        printf("Error: Authentication failed: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }
    printf("Authentication successful\n");

    // Mở thư mục nguồn
    dir = opendir(argv[4]);
    if (!dir) {
        printf("Error: Cannot open source directory %s\n", argv[4]);
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    // Sao chép từng tệp
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Chỉ xử lý tệp thông thường
            char source_path[1024];
            char dest_path[1024];

            snprintf(source_path, sizeof(source_path), "%s/%s", argv[4], entry->d_name);
            snprintf(dest_path, sizeof(dest_path), "%s/%s", argv[5], entry->d_name);

            copy_file(session, source_path, dest_path);
        }
    }

    // Đóng kết nối
    closedir(dir);
    ssh_disconnect(session);
    ssh_free(session);
    printf("Transfer completed\n");

    return 0;
}