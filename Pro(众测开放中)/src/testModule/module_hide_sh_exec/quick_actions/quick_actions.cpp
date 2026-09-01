#include "quick_actions.h"

#include <algorithm>
#include <cstring>

#include "kernel_module_kit_umbrella.h"

#include "json_helper.h"
#include "url_encode_utils.h"

namespace {

static void move_existing_to_back_or_append(std::vector<std::string>& items, const std::string& value) {
    auto it = std::find(items.begin(), items.end(), value);
    if (it != items.end()) {
        if (std::next(it) != items.end()) {
            std::rotate(it, std::next(it), items.end());
        }
    } else {
        items.push_back(value);
    }
}

} // namespace

void QuickActions::add(const std::vector<std::string>& cmd) {
    if (cmd.empty()) return;
    std::string json;
    kernel_module::read_string_disk_storage("quick_actions", json);
    std::vector<std::string> cmd_arr = parse_json(json);
    for (const auto& c : cmd) {
        std::vector<char> encoded_buf(c.size() * 3 + 1, '\0');
        url_encode(c.c_str(), encoded_buf.data());
        std::string encoded_str(encoded_buf.data(), std::strlen(encoded_buf.data()));
        move_existing_to_back_or_append(cmd_arr, encoded_str);
    }
    while (cmd_arr.size() > kMaxActions) {
        cmd_arr.erase(cmd_arr.begin());
    }
    json = json_array_from_set(cmd_arr);
    kernel_module::write_string_disk_storage("quick_actions", json.c_str());
}

std::string QuickActions::toJson() {
    std::string json;
    kernel_module::read_string_disk_storage("quick_actions", json);
    if (json.empty()) json = "[]";
    return json;
}
