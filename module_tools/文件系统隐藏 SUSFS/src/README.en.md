# SUSFS LKM

This repository is the local kernel side embedded in PLUS 4.6.0-dev1. The source baseline is upstream main `6753d9c189b058a5978eddd7d2093f95b5be68a2`, with the verified local readlink and visible-mount-root fixes retained.

The management ABI in `kernel/skp_sequential.h` exposes individual family clear/add operations and explicit manager-FD registration. Rules are fully initialized before RCU publication; removal keeps the required locks, references, callback draining and unload cleanup. The management layer has no revision/CAS, digest, WAL, asynchronous job, snapshot rollback, owner lease or permanent module pin.

PLUS stores one ordinary JSON configuration and applies it in path, kstat, map, redirect, mount order. Current local DDK validation covers android16-6.12 only. Host evidence and build receipts are under `work/plus-lkm-embedded-20261018/` and `build/plus-lkm-sequential/`. Device interception remains limited to the verified Probe app and Maple lab app; FD-count investigation stays deferred.
