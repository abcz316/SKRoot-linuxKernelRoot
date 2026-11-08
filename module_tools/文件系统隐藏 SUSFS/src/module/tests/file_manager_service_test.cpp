#include "../vendor/file_manager/file_manager_service.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace file_manager;

namespace {

void writeFile(const fs::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    assert(stream.good());
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    assert(stream.good());
}

std::string readFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::string readTextSession(TextTransferService& text, const TextOpenResult& opened, size_t limit) {
    std::string content;
    uint64_t offset = 0;
    Error error;
    while (true) {
        TextReadResult chunk;
        assert(text.readChunk(opened.session_id, offset, limit, chunk, error));
        std::vector<uint8_t> decoded;
        assert(TextTransferService::decodeBase64(chunk.base64_data, decoded));
        assert(chunk.offset == offset);
        assert(chunk.next_offset == offset + decoded.size());
        assert(chunk.next_offset <= opened.size);
        content.append(decoded.begin(), decoded.end());
        if (chunk.eof) break;
        assert(!decoded.empty());
        offset = chunk.next_offset;
    }
    assert(content.size() == opened.size);
    return content;
}

std::vector<std::string> editTemps(const fs::path& directory) {
    std::vector<std::string> result;
    for (const auto& entry : fs::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind(".skroot-edit-", 0) == 0) result.push_back(name);
    }
    std::sort(result.begin(), result.end());
    return result;
}

JobSnapshot waitForJob(FileJobManager& jobs, const std::string& id) {
    for (int i = 0; i < 500; ++i) {
        JobSnapshot value = jobs.snapshot(id);
        if (value.state == "completed" || value.state == "failed" || value.state == "cancelled") return value;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(false && "file job timeout");
    return {};
}

} // namespace

int main() {
    char temp_template[] = "/tmp/skroot-file-test-XXXXXX";
    char* root_raw = ::mkdtemp(temp_template);
    assert(root_raw);
    fs::path root(root_raw);

    FileService files;
    Error error;
    std::string normalized;
    assert(FileService::normalizeAbsolutePath((root / "a/../b").string(), normalized, error));
    assert(normalized == (root / "b").string());
    assert(!FileService::normalizeAbsolutePath("relative/path", normalized, error));

    fs::path source = root / "source";
    fs::path destination = root / "destination";
    fs::create_directories(source / "nested");
    fs::create_directories(destination);
    writeFile(source / "hello.txt", "hello\n");
    writeFile(source / "nested/config.json", "{\"ok\":true}\n");
    assert(::chmod((source / "hello.txt").c_str(), 0640) == 0);
    timespec source_times[2] = {{1700000000, 0}, {1700000001, 123000000}};
    assert(::utimensat(AT_FDCWD, (source / "hello.txt").c_str(), source_times, 0) == 0);
    const std::string xattr_value = "skroot-xattr";
    const bool has_user_xattr = ::setxattr((source / "hello.txt").c_str(), "user.skroot-test",
                                           xattr_value.data(), xattr_value.size(), 0) == 0;
    assert(::symlink("hello.txt", (source / "hello.link").c_str()) == 0);
    fs::create_directories(root / "linked-target");
    assert(::symlink((root / "linked-target").c_str(), (root / "linked-dir").c_str()) == 0);

    std::string listing;
    assert(files.list(root.string(), listing, error));
    assert(listing.find("\"name\":\"linked-dir\",\"type\":\"symlink\",\"isDir\":true") != std::string::npos);

    uint32_t created_mode = 0;
    fs::path blank_file = root / "空白.txt";
    assert(files.createFile(blank_file.string(), 0644, created_mode, error));
    struct stat blank_stat {};
    assert(::lstat(blank_file.c_str(), &blank_stat) == 0);
    assert(S_ISREG(blank_stat.st_mode) && blank_stat.st_size == 0);
    assert(created_mode == static_cast<uint32_t>(blank_stat.st_mode & 07777));
    assert(!files.createFile(blank_file.string(), 0644, created_mode, error));
    assert(error.code == "TARGET_EXISTS");
    assert(::symlink(blank_file.c_str(), (root / "blank-link").c_str()) == 0);
    assert(!files.createFile((root / "blank-link").string(), 0644, created_mode, error));
    assert(error.code == "TARGET_EXISTS");
    assert(files.createFile((root / ".env").string(), 0600, created_mode, error));
    assert(!files.createFile((root / "missing/file").string(), 0644, created_mode, error));
    assert(error.sys_errno == ENOENT);

    assert(::chmod(blank_file.c_str(), 06754) == 0);
    FileProperties blank_properties;
    assert(files.getProperties(blank_file.string(), blank_properties, error));
    assert(blank_properties.type == "file");
    assert(blank_properties.mode == 06754);
    std::vector<PrincipalEntry> users;
    std::vector<PrincipalEntry> groups;
    assert(files.listPrincipals(blank_file.string(), users, groups, error));
    assert(!users.empty() && !groups.empty());
    uint32_t resolved_uid = 0;
    uint32_t resolved_gid = 0;
    assert(files.resolveUser(std::to_string(::getuid()), resolved_uid, error));
    assert(files.resolveGroup(std::to_string(::getgid()), resolved_gid, error));
    assert(resolved_uid == static_cast<uint32_t>(::getuid()));
    assert(resolved_gid == static_cast<uint32_t>(::getgid()));

    FileJobManager jobs(files);

    fs::path property_root = root / "property-root";
    fs::create_directories(property_root / "nested");
    writeFile(property_root / "one.txt", "one");
    writeFile(property_root / "nested/two.txt", "two");
    assert(::symlink("one.txt", (property_root / "one.link").c_str()) == 0);
    OperationSpec property_root_only;
    property_root_only.type = OperationType::Properties;
    property_root_only.sources = {property_root.string()};
    property_root_only.properties.has_mode = true;
    property_root_only.properties.mode = 0711;
    std::string property_root_only_id;
    assert(jobs.start(property_root_only, property_root_only_id, error));
    assert(waitForJob(jobs, property_root_only_id).state == "completed");
    struct stat property_stat {};
    assert(::lstat(property_root.c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 0711);
    assert(::lstat((property_root / "nested").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) != 0711);

    OperationSpec property_mode;
    property_mode.type = OperationType::Properties;
    property_mode.sources = {property_root.string()};
    property_mode.properties.has_mode = true;
    property_mode.properties.mode = 0750;
    property_mode.properties.recursive_files = true;
    property_mode.properties.recursive_directories = false;
    std::string property_mode_id;
    assert(jobs.start(property_mode, property_mode_id, error));
    JobSnapshot property_mode_result = waitForJob(jobs, property_mode_id);
    assert(property_mode_result.state == "completed");
    assert(property_mode_result.warning_count > 0);
    assert(::lstat((property_root / "one.txt").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 0750);
    assert(::lstat((property_root / "nested").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) != 0750);

    OperationSpec property_directories;
    property_directories.type = OperationType::Properties;
    property_directories.sources = {property_root.string()};
    property_directories.properties.has_mode = true;
    property_directories.properties.mode = 02770;
    property_directories.properties.recursive_directories = true;
    std::string property_directories_id;
    assert(jobs.start(property_directories, property_directories_id, error));
    assert(waitForJob(jobs, property_directories_id).state == "completed");
    assert(::lstat((property_root / "nested").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 02770);
    assert(::lstat((property_root / "one.txt").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 0750);
    assert(::chmod((property_root / "one.txt").c_str(), 04750) == 0);

    OperationSpec property_owner;
    property_owner.type = OperationType::Properties;
    property_owner.sources = {property_root.string()};
    property_owner.properties.has_uid = true;
    property_owner.properties.uid = static_cast<uint32_t>(::getuid());
    property_owner.properties.has_gid = true;
    property_owner.properties.gid = static_cast<uint32_t>(::getgid());
    property_owner.properties.recursive_files = true;
    property_owner.properties.recursive_directories = true;
    std::string property_owner_id;
    assert(jobs.start(property_owner, property_owner_id, error));
    assert(waitForJob(jobs, property_owner_id).state == "completed");
    assert(::lstat((property_root / "one.txt").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 04750);
    OperationSpec copy;
    copy.type = OperationType::Copy;
    copy.conflict = ConflictPolicy::Overwrite;
    copy.sources = {source.string()};
    copy.destination = destination.string();
    std::string copy_id;
    assert(jobs.start(copy, copy_id, error));
    JobSnapshot copy_result = waitForJob(jobs, copy_id);
    assert(copy_result.state == "completed");
    assert(copy_result.processed_items == copy_result.total_items);
    assert(copy_result.success_count == copy_result.total_items);
    assert(readFile(destination / "source/hello.txt") == "hello\n");
    assert(readFile(destination / "source/nested/config.json") == "{\"ok\":true}\n");
    assert(fs::is_symlink(destination / "source/hello.link"));
    struct stat copied_stat {};
    assert(::lstat((destination / "source/hello.txt").c_str(), &copied_stat) == 0);
    assert((copied_stat.st_mode & 0777) == 0640);
    assert(copied_stat.st_mtim.tv_sec == source_times[1].tv_sec);
    assert(copied_stat.st_mtim.tv_nsec == source_times[1].tv_nsec);
    if (has_user_xattr) {
        std::vector<char> copied_xattr(xattr_value.size());
        assert(::getxattr((destination / "source/hello.txt").c_str(), "user.skroot-test",
                          copied_xattr.data(), copied_xattr.size()) == static_cast<ssize_t>(copied_xattr.size()));
        assert(std::string(copied_xattr.begin(), copied_xattr.end()) == xattr_value);
    }

    OperationSpec duplicate_copy = copy;
    duplicate_copy.sources.assign(501, (source / "hello.txt").string());
    std::string duplicate_id;
    assert(jobs.start(duplicate_copy, duplicate_id, error));
    JobSnapshot duplicate_result = waitForJob(jobs, duplicate_id);
    assert(duplicate_result.state == "completed");
    assert(duplicate_result.total_items == 1);

    fs::path inside_link = root / "inside-source-link";
    assert(::symlink((source / "nested").c_str(), inside_link.c_str()) == 0);
    OperationSpec self_copy = copy;
    self_copy.destination = inside_link.string();
    std::string rejected_id;
    assert(!jobs.start(self_copy, rejected_id, error));
    assert(error.code == "INVALID_DESTINATION");
    fs::remove(inside_link);

    writeFile(source / "hello.txt", "changed\n");
    OperationSpec skip = copy;
    skip.conflict = ConflictPolicy::Skip;
    std::string skip_id;
    assert(jobs.start(skip, skip_id, error));
    JobSnapshot skip_result = waitForJob(jobs, skip_id);
    assert(skip_result.state == "completed");
    assert(skip_result.skipped_count > 0);
    assert(readFile(destination / "source/hello.txt") == "hello\n");

    fs::path move_source = root / "move-me.txt";
    writeFile(move_source, "move");
    OperationSpec move;
    move.type = OperationType::Move;
    move.conflict = ConflictPolicy::Overwrite;
    move.sources = {move_source.string()};
    move.destination = destination.string();
    std::string move_id;
    assert(jobs.start(move, move_id, error));
    assert(waitForJob(jobs, move_id).state == "completed");
    assert(!fs::exists(move_source));
    assert(readFile(destination / "move-me.txt") == "move");

    fs::path move_tree = root / "move-tree";
    fs::create_directories(move_tree / "nested");
    writeFile(move_tree / "nested/data.txt", "tree");
    move.sources = {move_tree.string()};
    std::string move_tree_id;
    assert(jobs.start(move, move_tree_id, error));
    JobSnapshot move_tree_result = waitForJob(jobs, move_tree_id);
    assert(move_tree_result.state == "completed");
    assert(move_tree_result.processed_items == move_tree_result.total_items);
    assert(move_tree_result.success_count == move_tree_result.total_items);
    assert(readFile(destination / "move-tree/nested/data.txt") == "tree");

    assert(!files.renamePath("/", (root / "renamed-root").string(), error));
    assert(error.code == "ROOT_OPERATION_BLOCKED");
    fs::path rename_source = root / "rename-source.txt";
    fs::path rename_target = root / "rename-target.txt";
    writeFile(rename_source, "source");
    writeFile(rename_target, "target");
    assert(!files.renamePath(rename_source.string(), rename_target.string(), error));
    assert(error.code == "TARGET_EXISTS");
    assert(readFile(rename_source) == "source");
    assert(readFile(rename_target) == "target");

    struct stat root_stat {};
    struct stat shared_stat {};
    if (::stat(root.c_str(), &root_stat) == 0 && ::stat("/dev/shm", &shared_stat) == 0
        && root_stat.st_dev != shared_stat.st_dev && ::access("/dev/shm", W_OK) == 0) {
        fs::path shared_destination = fs::path("/dev/shm") / ("skroot-cross-device-" + randomHex(6));
        fs::create_directories(shared_destination);
        fs::path cross_source = root / "cross-device.txt";
        writeFile(cross_source, "cross-device");
        move.sources = {cross_source.string()};
        move.destination = shared_destination.string();
        std::string cross_id;
        assert(jobs.start(move, cross_id, error));
        JobSnapshot cross_result = waitForJob(jobs, cross_id);
        assert(cross_result.state == "completed");
        assert(!fs::exists(cross_source));
        assert(readFile(shared_destination / "cross-device.txt") == "cross-device");
        fs::remove_all(shared_destination);
        move.destination = destination.string();
    }

    OperationSpec remove;
    remove.type = OperationType::Delete;
    remove.sources = {(destination / "source").string()};
    std::string remove_id;
    assert(jobs.start(remove, remove_id, error));
    assert(waitForJob(jobs, remove_id).state == "completed");
    assert(!fs::exists(destination / "source"));

    fs::path fake_apk = root / "应用 安装包.apk";
    std::string fake_apk_content = "not-a-real-apk-but-package-manager-validates-it";
    fake_apk_content.append(256 * 1024, 'A');
    writeFile(fake_apk, fake_apk_content);
    fs::path installer = root / "fake-installer.sh";
    fs::path installer_args = root / "installer-args.txt";
    fs::path installer_stdin = root / "installer-stdin.apk";
    writeFile(installer, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SKROOT_TEST_APK_ARGS\"\ncat > \"$SKROOT_TEST_APK_STDIN\"\necho Success\n");
    assert(::chmod(installer.c_str(), 0755) == 0);
    assert(::setenv("SKROOT_TEST_APK_INSTALLER", installer.c_str(), 1) == 0);
    assert(::setenv("SKROOT_TEST_APK_ARGS", installer_args.c_str(), 1) == 0);
    assert(::setenv("SKROOT_TEST_APK_STDIN", installer_stdin.c_str(), 1) == 0);
    OperationSpec install_apk;
    install_apk.type = OperationType::InstallApk;
    install_apk.sources = {fake_apk.string()};
    std::string install_id;
    assert(jobs.start(install_apk, install_id, error));
    JobSnapshot install_result = waitForJob(jobs, install_id);
    assert(install_result.state == "completed");
    assert(install_result.exit_code == 0 && install_result.success_count == 1);
    assert(install_result.result_code == "APK_INSTALL_COMPLETED");
    const std::string install_args = readFile(installer_args);
    assert(install_args == std::string("package\ninstall\n-r\n-d\n--user\n0\n-S\n")
        + std::to_string(fake_apk_content.size()) + "\n");
    assert(readFile(installer_stdin) == fake_apk_content);

    fs::path messenger_apk = root / "QQ接收的应用.apk.1";
    writeFile(messenger_apk, fake_apk_content);
    install_apk.sources = {messenger_apk.string()};
    assert(jobs.start(install_apk, install_id, error));
    JobSnapshot messenger_install = waitForJob(jobs, install_id);
    assert(messenger_install.state == "completed");
    assert(messenger_install.result_code == "APK_INSTALL_COMPLETED");
    assert(readFile(installer_stdin) == fake_apk_content);
    install_apk.sources = {fake_apk.string()};

    // Stealth-first mode never creates an APK staging file.  If an OEM still
    // rejects the anonymous pipe, expose the original package-manager error.
    fs::path apk_stage = root / "apk-stage";
    fs::create_directories(apk_stage);
    assert(::setenv("SKROOT_TEST_APK_STAGE_DIR", apk_stage.c_str(), 1) == 0);
    writeFile(installer,
              "#!/bin/sh\n"
              "echo 'Error: failed to write; fstat failed: EACCES (Permission denied)' >&2\n"
              "exit 1\n");
    assert(::chmod(installer.c_str(), 0755) == 0);
    assert(jobs.start(install_apk, install_id, error));
    JobSnapshot install_pipe_failure = waitForJob(jobs, install_id);
    assert(install_pipe_failure.state == "failed");
    assert(install_pipe_failure.result_code == "APK_INSTALL_FAILED");
    assert(install_pipe_failure.result_message.find("fstat failed") != std::string::npos);
    assert(fs::directory_iterator(apk_stage) == fs::directory_iterator());

    writeFile(installer, "#!/bin/sh\necho 'Failure [INSTALL_FAILED_TEST]' >&2\nexit 7\n");
    assert(::chmod(installer.c_str(), 0755) == 0);
    assert(jobs.start(install_apk, install_id, error));
    JobSnapshot install_failure = waitForJob(jobs, install_id);
    assert(install_failure.state == "failed" && install_failure.exit_code == 7);
    assert(install_failure.result_code == "APK_INSTALL_FAILED");
    assert(!install_failure.errors.empty() && install_failure.errors[0].code == "APK_INSTALL_FAILED");
    assert(install_failure.errors[0].message.find(fake_apk.string()) == std::string::npos);

    writeFile(installer, "#!/bin/sh\nsleep 30\necho Success\n");
    assert(::chmod(installer.c_str(), 0755) == 0);
    assert(jobs.start(install_apk, install_id, error));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(jobs.cancel(install_id, error));
    JobSnapshot install_cancelled = waitForJob(jobs, install_id);
    assert(install_cancelled.state == "cancelled");
    assert(install_cancelled.result_code == "APK_INSTALL_CANCELLED");

    assert(::setenv("SKROOT_TEST_APK_TIMEOUT_SECONDS", "1", 1) == 0);
    assert(jobs.start(install_apk, install_id, error));
    JobSnapshot install_timeout = waitForJob(jobs, install_id);
    assert(install_timeout.state == "failed");
    assert(install_timeout.result_code == "APK_INSTALL_TIMEOUT");
    assert(!install_timeout.errors.empty() && install_timeout.errors[0].code == "APK_INSTALL_TIMEOUT");
    (void)::unsetenv("SKROOT_TEST_APK_TIMEOUT_SECONDS");

    OperationSpec invalid_apk = install_apk;
    invalid_apk.sources = {(root / "plain.txt").string()};
    writeFile(root / "plain.txt", "plain");
    std::string invalid_apk_id;
    assert(!jobs.start(invalid_apk, invalid_apk_id, error));
    assert(error.code == "INVALID_APK");
    writeFile(root / "renamed.apk.2", "plain");
    invalid_apk.sources = {(root / "renamed.apk.2").string()};
    assert(!jobs.start(invalid_apk, invalid_apk_id, error));
    assert(error.code == "INVALID_APK");
    assert(::symlink(fake_apk.c_str(), (root / "linked.apk").c_str()) == 0);
    invalid_apk.sources = {(root / "linked.apk").string()};
    assert(!jobs.start(invalid_apk, invalid_apk_id, error));
    assert(error.code == "INVALID_APK");
    (void)::unsetenv("SKROOT_TEST_APK_INSTALLER");
    (void)::unsetenv("SKROOT_TEST_APK_ARGS");
    (void)::unsetenv("SKROOT_TEST_APK_STDIN");
    (void)::unsetenv("SKROOT_TEST_APK_STAGE_DIR");

    JobSnapshot cancelled;
    cancelled.id = "cancel-test";
    OperationSpec direct = copy;
    std::atomic<bool> cancel_requested{true};
    files.runOperation(direct, cancel_requested, [](const JobSnapshot&) {}, cancelled);
    assert(cancelled.state == "cancelled");

    TextTransferService text;
    TextOpenResult empty_opened;
    assert(text.openText(blank_file.string(), empty_opened, error));
    assert(empty_opened.size == 0 && empty_opened.version.size == 0);
    assert(!empty_opened.read_only);
    assert(readTextSession(text, empty_opened, 1).empty());
    std::string empty_save_id;
    assert(text.startSave(blank_file.string(), empty_opened.version, 0, false, empty_save_id, error));
    FileVersion empty_saved_version;
    assert(text.commitSave(empty_save_id, false, empty_saved_version, error));
    assert(readFile(blank_file).empty());

    // procfs reports zero bytes in stat even when its generated text is nonempty.
    // These are host reads only; the save rejection must happen before creating a temp file.
    const fs::path tainted_path = "/proc/sys/kernel/tainted";
    if (::access(tainted_path.c_str(), R_OK) == 0) {
        struct stat tainted_stat {};
        assert(::stat(tainted_path.c_str(), &tainted_stat) == 0);
        assert(tainted_stat.st_size == 0);
        TextOpenResult tainted_opened;
        assert(text.openText(tainted_path.string(), tainted_opened, error));
        assert(tainted_opened.read_only);
        assert(tainted_opened.version.size == 0 && tainted_opened.size > 0);
        const std::string tainted = readTextSession(text, tainted_opened, 1);
        assert(tainted.back() == '\n');
        assert(tainted.find_first_not_of("0123456789\n") == std::string::npos);
        const auto temps_before = editTemps(tainted_path.parent_path());
        for (bool force : {false, true}) {
            std::string rejected_save_id;
            assert(!text.startSave(tainted_path.string(), tainted_opened.version,
                                   tainted_opened.size, force, rejected_save_id, error));
            assert(error.code == "READ_ONLY_FILE");
            assert(rejected_save_id.empty() && !text.hasActiveSave());
            assert(editTemps(tainted_path.parent_path()) == temps_before);
        }
    }

    // sysfs commonly reports a page-sized stat length, not its generated text length.
    const fs::path sysfs_path = "/sys/kernel/uevent_seqnum";
    if (::access(sysfs_path.c_str(), R_OK) == 0) {
        struct stat sysfs_stat {};
        assert(::stat(sysfs_path.c_str(), &sysfs_stat) == 0);
        TextOpenResult sysfs_opened;
        assert(text.openText(sysfs_path.string(), sysfs_opened, error));
        assert(sysfs_opened.read_only);
        assert(sysfs_opened.version.size == static_cast<uint64_t>(sysfs_stat.st_size));
        const std::string sysfs_text = readTextSession(text, sysfs_opened, 2);
        assert(!sysfs_text.empty() && sysfs_text.back() == '\n');
        assert(sysfs_text.find_first_not_of("0123456789\n") == std::string::npos);
        std::string rejected_save_id;
        assert(!text.startSave(sysfs_path.string(), sysfs_opened.version,
                               sysfs_opened.size, true, rejected_save_id, error));
        assert(error.code == "READ_ONLY_FILE" && !text.hasActiveSave());
    }

    // Change only this host test process's comm between chunks. A single opened
    // procfs session must keep the captured content rather than regenerate each chunk.
    char original_comm[16] = {};
    assert(::prctl(PR_GET_NAME, original_comm) == 0);
    assert(::prctl(PR_SET_NAME, "skroot-before") == 0);
    TextOpenResult proc_opened;
    assert(text.openText("/proc/self/stat", proc_opened, error));
    assert(proc_opened.read_only && proc_opened.size > 32 && proc_opened.version.size == 0);
    TextReadResult proc_first;
    assert(text.readChunk(proc_opened.session_id, 0, 32, proc_first, error));
    assert(!proc_first.eof);
    assert(::prctl(PR_SET_NAME, "skroot-after") == 0);
    TextReadResult proc_repeated;
    assert(text.readChunk(proc_opened.session_id, 0, 32, proc_repeated, error));
    assert(proc_repeated.base64_data == proc_first.base64_data);
    std::vector<uint8_t> proc_decoded;
    assert(TextTransferService::decodeBase64(proc_first.base64_data, proc_decoded));
    std::string proc_content(proc_decoded.begin(), proc_decoded.end());
    uint64_t proc_offset = proc_first.next_offset;
    while (true) {
        TextReadResult proc_chunk;
        assert(text.readChunk(proc_opened.session_id, proc_offset, 7, proc_chunk, error));
        assert(TextTransferService::decodeBase64(proc_chunk.base64_data, proc_decoded));
        assert(proc_chunk.offset == proc_offset);
        assert(proc_chunk.next_offset == proc_offset + proc_decoded.size());
        proc_content.append(proc_decoded.begin(), proc_decoded.end());
        if (proc_chunk.eof) break;
        assert(!proc_decoded.empty());
        proc_offset = proc_chunk.next_offset;
    }
    assert(::prctl(PR_SET_NAME, original_comm) == 0);
    assert(proc_content.size() == proc_opened.size);
    assert(proc_content.find("(skroot-before)") != std::string::npos);
    assert(proc_content.find("skroot-after") == std::string::npos);

    fs::path text_path = root / "edit.txt";
    writeFile(text_path, "alpha\nbeta\n");
    TextOpenResult opened;
    assert(text.openText(text_path.string(), opened, error));
    assert(!opened.read_only && opened.size == opened.version.size);
    TextReadResult chunk;
    assert(text.readChunk(opened.session_id, 0, 4, chunk, error));
    std::vector<uint8_t> decoded;
    assert(TextTransferService::decodeBase64(chunk.base64_data, decoded));
    assert(std::string(decoded.begin(), decoded.end()) == "alph");
    TextReadResult remainder;
    assert(text.readChunk(opened.session_id, chunk.next_offset, kMaxTransferChunkBytes, remainder, error));
    assert(remainder.eof);
    assert(!text.readChunk(opened.session_id, remainder.next_offset, 1, chunk, error));
    assert(error.code == "TEXT_SESSION_NOT_FOUND");

    std::string replacement(kMaxTransferChunkBytes + 17, 'x');
    replacement += "\n";
    std::string save_id;
    assert(text.startSave(text_path.string(), opened.version, replacement.size(), false, save_id, error));
    assert(!TextTransferService::decodeBase64("YQ==Yg==", decoded));
    uint64_t received = 0;
    std::string second_save_id;
    assert(!text.startSave(text_path.string(), opened.version, replacement.size(), false, second_save_id, error));
    assert(error.code == "SAVE_BUSY");
    for (size_t offset = 0; offset < replacement.size(); offset += kMaxTransferChunkBytes) {
        const size_t size = std::min(kMaxTransferChunkBytes, replacement.size() - offset);
        const std::string encoded = TextTransferService::encodeBase64(
            reinterpret_cast<const uint8_t*>(replacement.data() + offset), size);
        assert(text.writeChunk(save_id, offset, encoded, received, error));
    }
    assert(received == replacement.size());
    writeFile(text_path, "external change\n");
    FileVersion saved_version;
    assert(!text.commitSave(save_id, false, saved_version, error));
    assert(error.code == "FILE_CHANGED");
    assert(text.commitSave(save_id, true, saved_version, error));
    assert(readFile(text_path) == replacement);

    fs::path changing_path = root / "changing.txt";
    writeFile(changing_path, "first version\n");
    TextOpenResult changing_opened;
    assert(text.openText(changing_path.string(), changing_opened, error));
    assert(text.readChunk(changing_opened.session_id, 0, 3, chunk, error));
    assert(!chunk.eof);
    writeFile(changing_path, "second version has a different length\n");
    assert(!text.readChunk(changing_opened.session_id, chunk.next_offset, 3, chunk, error));
    assert(error.code == "FILE_CHANGED");

    fs::path invalid_path = root / "invalid.txt";
    writeFile(invalid_path, std::string("\xff\xfe", 2));
    assert(!text.openText(invalid_path.string(), opened, error));
    assert(error.code == "INVALID_UTF8");

    fs::path too_large = root / "large.txt";
    {
        std::ofstream stream(too_large, std::ios::binary);
        stream.seekp(static_cast<std::streamoff>(kMaxTextFileBytes));
        stream.put('x');
    }
    assert(!text.openText(too_large.string(), opened, error));
    assert(error.code == "TEXT_TOO_LARGE");

    fs::path exact_limit = root / "exact-limit.txt";
    writeFile(exact_limit, std::string(static_cast<size_t>(kMaxTextFileBytes), 'a'));
    assert(text.openText(exact_limit.string(), opened, error));
    assert(opened.size == kMaxTextFileBytes);

    jobs.shutdown();
    text.shutdown();
    fs::remove_all(root);
    std::cout << "file_manager_service_test: OK\n";
    return 0;
}
