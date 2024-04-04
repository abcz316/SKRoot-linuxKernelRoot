#ifndef _KERNEL_ROOT_KIT_PARASITE_PATCH_ELF_H_
#define _KERNEL_ROOT_KIT_PARASITE_PATCH_ELF_H_
#include <iostream>
namespace kernel_root {
int parasite_check_so_link(const char* original_so_file_path,
					   const char* implant_so_file_path);

int parasite_start_link_so(const char* original_so_file_path,
					   const char* implant_so_file_path);
}
#endif /* _KERNEL_ROOT_KIT_PARASITE_PATCH_ELF_H_ */
