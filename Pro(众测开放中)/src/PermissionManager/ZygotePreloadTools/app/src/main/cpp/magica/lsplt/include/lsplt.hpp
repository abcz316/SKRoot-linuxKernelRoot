#pragma once

#include <sys/types.h>

#include <string>
#include <string_view>
#include <vector>

/// \namespace lsplt
namespace lsplt {
inline namespace v2 {

/// \struct MapInfo
/// \brief An entry that describes a line in /proc/self/maps. You can obtain a list of these entries
/// by calling #Scan().
struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    std::string path;

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \param[in] pid The process id to scan. This is "self" by default.
    /// \return A list of \ref MapInfo entries.
    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> Scan(std::string_view pid = "self");
};

/// \brief Register a hook to a function by inode. For so within an archive, you should use
/// #RegisterHook(ino_t, uintptr_t, size_t, std::string_view, void *, void **) instead.
/// \param[in] dev The device number of the memory region.
/// \param[in] inode The inode of the library to hook. You can obtain the inode by #stat() or by finding
/// the library in the list returned by #lsplt::v1::MapInfo::Scan().
/// \param[in] symbol The function symbol to hook.
/// \param[in] callback The callback function pointer to call when the function is called.
/// \param[out] backup The backup function pointer which can call the original function. This is
/// optional.
/// \return Whether the hook is successfully registered.
/// \note This function is thread-safe.
/// \note \p backup will not be available until #CommitHook() is called.
/// \note \p backup will be nullptr if the hook fails.
/// \note You can unhook the function by calling this function with \p callback set to the backup
/// set by previous call.
/// \note LSPlt will backup the hook memory region and restore it when the
/// hook is restored to its original function pointer so that there won't be dirty pages. LSPlt will
/// do hooks on a copied memory region so that the original memory region will not be modified. You
/// can invalidate this behaviour and hook the original memory region by calling
/// #InvalidateBackup().
/// \see #CommitHook()
/// \see #InvalidateBackup()
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol,
                                                               void *callback, void **backup);

/// \brief Register a hook to a function by inode with offset range. This is useful when hooking
/// a library that is directly loaded from an archive without extraction.
/// \param[in] dev The device number of the memory region.
/// \param[in] inode The inode of the library to hook. You can obtain the inode by #stat() or by finding
/// the library in the list returned by #lsplt::v1::MapInfo::Scan().
/// \param[in] offset The to the library in the file.
/// \param[in] size The upper bound size to the library in the file.
/// \param[in] symbol The function symbol to hook.
/// \param[in] callback The callback function pointer to call when the function is called.
/// \param[out] backup The backup function pointer which can call the original function. This is
/// optional.
/// \return Whether the hook is successfully registered.
/// \note This function is thread-safe.
/// \note \p backup will not be available until #CommitHook() is called.
/// \note \p backup will be nullptr if the hook fails.
/// \note You can unhook the function by calling this function with \p callback set to the backup
/// set by previous call.
/// \note LSPlt will backup the hook memory region and restore it when the
/// hook is restored to its original function pointer so that there won't be dirty pages. LSPlt will
/// do hooks on a copied memory region so that the original memory region will not be modified. You
/// can invalidate this behaviour and hook the original memory region by calling
/// #InvalidateBackup().
/// \note You can get the offset range of the library by getting its entry offset and size in the
/// zip file.
/// \note According to the Android linker specification, the \p offset must be page aligned.
/// \note The \p offset must be accurate, otherwise the hook may fail because the ELF header
/// cannot be found.
/// \note The \p size can be inaccurate but should be larger or equal to the library size,
/// otherwise the hook may fail when the hook pointer is beyond the range.
/// \note The behaviour of this function is undefined if \p offset + \p size is larger than the
/// the maximum value of \p size_t.
/// \see #CommitHook()
/// \see #InvalidateBackup()
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset,
                                                               size_t size, std::string_view symbol,
                                                               void *callback, void **backup);
/// \brief Commit all registered hooks.
/// \return Whether all hooks are successfully committed. If any of the hooks fail to commit,
/// the result is false.
/// \note This function is thread-safe.
/// \note The return value indicates whether all hooks are successfully committed. You can
/// determine which hook fails by checking the backup function pointer of #RegisterHook().
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool CommitHook();

/// \brief Invalidate backup memory regions
/// Normally LSPlt will backup the hooked memory region and do hook on a copied anonymous memory
/// region, and restore the original memory region when the hook is unregistered
/// (when the callback of #RegisterHook() is the original function). This function will restore
/// the backup memory region and do all existing hooks on the original memory region.
/// \return Whether all hooks are successfully invalidated. If any of the hooks fail to invalidate,
/// the result is false.
/// \note This function is thread-safe.
/// \note This will be automatically called when the library is unloaded.
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool InvalidateBackup();
}  // namespace v2
}  // namespace lsplt
