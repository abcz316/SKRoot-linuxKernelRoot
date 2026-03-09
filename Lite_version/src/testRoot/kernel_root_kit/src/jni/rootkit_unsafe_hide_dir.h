#pragma once
#include <iostream>

namespace kernel_root {
KRootErr unsafe_create_su_hide_dir(const char* str_root_key);

KRootErr unsafe_del_su_hide_dir(const char* str_root_key);

KRootErr unsafe_clean_older_hide_dir(const char* root_key);
} // namespace kernel_root
