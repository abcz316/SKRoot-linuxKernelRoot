#pragma once
#include <string>
#include <unordered_map>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include "civetweb-1.16/include/CivetServer.h"

namespace kernel_module {
namespace webui {

/***************************************************************************
 * KV 字典类型（HTTP 参数 / 额外响应头）
 * 说明:
 *   - key/value 均为 UTF-8 字符串（按字节存储，不做编码转换）
 *   - 用于 extra_headers 时：key=Header-Name，value=Header-Value
 ***************************************************************************/
using KvMap = std::unordered_map<std::string, std::string>;

/***************************************************************************
 * 获取 HTTP 状态码对应的原因短语（Reason-Phrase）
 * 参数: status     HTTP 状态码（如 200/404/500）
 * 返回: 指向静态常量字符串的指针（无需释放）
 * 说明:
 *   - 仅覆盖常用状态码；未覆盖的状态码默认返回 "OK"
 *   - 用于拼接响应行：HTTP/1.1 <status> <reason>
 ***************************************************************************/
static const char* reason_phrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

/***************************************************************************
 * 获取当前连接的请求信息结构体
 * 参数: conn       CivetWeb 连接对象
 * 返回: 请求信息指针；失败返回 nullptr
 * 说明:
 *   - 返回的指针由 CivetWeb 内部管理，生命周期通常仅在本次请求处理期间有效
 *   - 常用字段：request_method / local_uri / query_string / content_length 等
 ***************************************************************************/
static const struct mg_request_info* req_info(struct mg_connection* conn) {
    return conn ? mg_get_request_info(conn) : nullptr;
}

/***************************************************************************
 * 获取请求路径（不含 query）
 * 参数: conn        CivetWeb 连接对象
 * 返回: std::string 请求路径（例如 "/getVersion"）
 ***************************************************************************/
static std::string get_request_path(struct mg_connection* conn) {
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    return req_info->local_uri ? req_info->local_uri : "/";
}

/***************************************************************************
 * 获取 URL 查询参数字符串
 * 参数: conn        CivetWeb 连接对象
 * 返回: std::string URL 查询参数字符串（'?' 后面的部分，不含 '?'；无则返回空字符串）
 ***************************************************************************/
static std::string get_request_query_string(struct mg_connection* conn) {
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    return req_info->query_string ? req_info->query_string : "";
}

/***************************************************************************
 * 读取请求 body（带大小限制）
 * 参数: conn        CivetWeb 连接对象
 *       out         [输出] 读取到的 body 数据（按原始字节拼接，可能包含 '\0'）
 *       max_bytes   最大允许读取的字节数（默认 256KB）
 * 返回: BodyReadStatus 状态码
 * 说明:
 *   - 若 content_length > 0：会预先判断是否超限，并在读取后校验是否读够
 *   - 若 content_length <= 0：持续读取直到 mg_read 返回 0（读完/关闭）
 *   - out 使用 append(buf, n)，不会把 buf 当 C 字符串处理
 ***************************************************************************/
enum class BodyReadStatus {
    OK = 0,     // 成功
    TOO_LARGE,  // 超出上限
    READ_ERROR, // 读取异常
    INCOMPLETE  // 长度不符
};
static BodyReadStatus read_request_body(struct mg_connection* conn,
                                       std::string& out,
                                       size_t max_bytes = 256 * 1024) {
    out.clear();
    auto ri = req_info(conn);
    long long content_len = (ri ? ri->content_length : -1);
    if (content_len > 0) {
        if ((unsigned long long)content_len > (unsigned long long)max_bytes) return BodyReadStatus::TOO_LARGE;
        out.reserve((size_t)content_len);
    }
    char buf[8192];
    size_t total = 0;
    while (true) {
        int n = mg_read(conn, buf, (int)sizeof(buf));
        if (n < 0) return BodyReadStatus::READ_ERROR;
        if (n == 0) break;
        total += (size_t)n;
        if (total > max_bytes) return BodyReadStatus::TOO_LARGE;
        out.append(buf, (size_t)n);
        if (content_len > 0 && total >= (size_t)content_len) break;
    }
    if (content_len > 0 && total < (size_t)content_len) return BodyReadStatus::INCOMPLETE;
    return BodyReadStatus::OK;
}

/***************************************************************************
 * 发送二进制响应（统一封装）
 * 参数: conn            CivetWeb 连接对象
 *       status          HTTP 状态码（200/404/500...）
 *       content_type    Content-Type（可为 nullptr，默认 application/octet-stream）
 *       data            响应体数据指针（可为 nullptr）
 *       size            响应体长度（字节数）
 *       extra_headers   额外响应头（可为 nullptr）
 * 返回: true 表示已向 conn 写入响应；false 表示参数不合法或 conn 为空
 ***************************************************************************/
static bool send_bytes(struct mg_connection* conn, int status, const char* content_type, const void* data, size_t size, const KvMap* extra_headers = nullptr) {
    if (!conn) return false;
    const char* reason = reason_phrase(status);
    if (!content_type) content_type = "application/octet-stream";
    mg_printf(conn, "HTTP/1.1 %d %s\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %llu\r\n"
              "Connection: close\r\n", status, reason, content_type, (unsigned long long)size);
    if (extra_headers) {
        for (const auto& kv : *extra_headers) mg_printf(conn, "%s: %s\r\n", kv.first.c_str(), kv.second.c_str());
    }
    mg_printf(conn, "\r\n");
    if (size > 0 && data) mg_write(conn, data, size);
    return true;
}

/***************************************************************************
 * 发送 HTML 响应（UTF-8）
 * 参数: conn            CivetWeb 连接对象
 *       status          HTTP 状态码
 *       html            HTML 内容（UTF-8）
 *       extra_headers   额外响应头（可为 nullptr）
 * 返回: true 表示已写入响应；false 表示失败
 * 说明:
 *   - Content-Type 固定为 text/html; charset=utf-8
 ***************************************************************************/
static bool send_html(struct mg_connection* conn, int status, const std::string& html, const KvMap* extra_headers = nullptr) {
    return send_bytes(conn, status, "text/html; charset=utf-8", html.data(), html.size(), extra_headers);
}

/***************************************************************************
 * 发送文本响应（UTF-8）
 * 参数: conn            CivetWeb 连接对象
 *       status          HTTP 状态码
 *       text            文本内容（UTF-8）
 *       extra_headers   额外响应头（可为 nullptr）
 *       content_type    Content-Type（默认 text/plain; charset=utf-8）
 * 返回: true 表示已写入响应；false 表示失败
 ***************************************************************************/
static bool send_text(struct mg_connection* conn, int status, const std::string& text, const KvMap* extra_headers = nullptr) {
    return send_bytes(conn, status, "text/plain; charset=utf-8", text.data(), text.size(), extra_headers);
}

/***************************************************************************
 * 发送 JSON 响应（UTF-8）
 * 参数: conn            CivetWeb 连接对象
 *       status          HTTP 状态码
 *       json            JSON 字符串（UTF-8，调用方保证为合法 JSON）
 *       extra_headers   额外响应头（可为 nullptr）
 * 返回: true 表示已写入响应；false 表示失败
 * 说明:
 *   - Content-Type 固定为 application/json; charset=utf-8
 ***************************************************************************/
static bool send_json(struct mg_connection* conn, int status, const std::string& json, const KvMap* extra_headers = nullptr) {
    return send_bytes(conn, status, "application/json; charset=utf-8", json.data(), json.size(), extra_headers);
}

} // namespace webui
} // namespace kernel_module
