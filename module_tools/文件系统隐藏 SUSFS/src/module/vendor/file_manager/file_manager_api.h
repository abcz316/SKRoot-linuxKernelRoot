#pragma once

#include "file_manager_service.h"
#include "image_preview_service.h"
#include "archive_browser_service.h"

#include <mutex>
#include <string>

namespace file_manager {

struct ApiReply {
    int status = 200;
    std::string body;
};

class FileManagerApi {
public:
    FileManagerApi();
    ~FileManagerApi();

    void configure(const std::string& special_comm);
    ApiReply handle(const std::string& path, const std::string& body);
    bool isJobActive() const;
    void requestStop();
    void shutdown();

private:
    ApiReply handleSettingsGet();
    ApiReply handleSettingsSetHome(const std::string& body);
    ApiReply handlePlacesGet();
    ApiReply handlePlacesSet(const std::string& body);
    ApiReply handleList(const std::string& body);
    ApiReply handleMkdir(const std::string& body);
    ApiReply handleCreate(const std::string& body);
    ApiReply handleRename(const std::string& body);
    ApiReply handlePropertiesGet(const std::string& body);
    ApiReply handlePrincipalsList(const std::string& body);
    ApiReply handleJobStart(const std::string& body);
    ApiReply handleJobStatus(const std::string& body);
    ApiReply handleJobCancel(const std::string& body);
    ApiReply handleTextOpen(const std::string& body);
    ApiReply handleTextRead(const std::string& body);
    ApiReply handleTextSaveStart(const std::string& body);
    ApiReply handleTextSaveChunk(const std::string& body);
    ApiReply handleTextSaveCommit(const std::string& body);
    ApiReply handleTextSaveAbort(const std::string& body);
    ApiReply handleImageOpen(const std::string& body);
    ApiReply handleImageRead(const std::string& body);
    ApiReply handleImageClose(const std::string& body);
    ApiReply handleArchive(const std::string& path, const std::string& body);

    FileService m_files;
    FileJobManager m_jobs;
    TextTransferService m_text;
    ImagePreviewService m_images;
    ArchiveBrowserService m_archives;
    std::mutex m_write_mu;
    std::atomic<bool> m_stop_requested{false};
};

ApiReply makeApiError(const Error& error, int status = 0);

} // namespace file_manager
