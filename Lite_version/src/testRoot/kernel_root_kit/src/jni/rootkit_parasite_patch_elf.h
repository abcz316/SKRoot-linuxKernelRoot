#pragma once
#include <iostream>
namespace kernel_root {
int parasite_check_so_link(const char* original_so_file_path,
					   const char* implant_so_file_path);

int parasite_start_link_so(const char* original_so_file_path,
					   const char* implant_so_file_path);
}