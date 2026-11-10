#pragma once
#include <iostream>
#include <string>
#include "patch_base.h"

class PatchCommitCred : public PatchBase {
public:
	PatchCommitCred(const PatchBase& patch_base, uint64_t commit_creds);
	~PatchCommitCred();

	KModErr patch_commit_cred(uint32_t target_uid);
private:
	uint64_t m_commit_creds = 0;
};
