"""Run the vendored SUSFS file-manager service/API regressions on a Linux host."""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[3]
vendor = root / 'susfs4skp-lkm/module/vendor/file_manager'
tests = Path(__file__).resolve().parent
build = root / 'build/susfs-proc-read-tests'
evidence = root / 'work/susfs-proc-read-fix'
build.mkdir(parents=True, exist_ok=True)
evidence.mkdir(parents=True, exist_ok=True)
sdk = root / 'dependencies/SKRoot-linuxKernelRoot/Pro(众测开放中)/src/testModule/kernel_module_kit/include'
flags = ['-std=c++20', '-O0', '-g', '-pthread', '-I' + str(vendor), '-I' + str(sdk), '-I' + str(vendor / 'third_party/libarchive/include')]
libraries = ['-l:libarchive.so.13', '-l:liblzma.so.5', '-lz']
cxx = os.environ.get('CXX', 'g++')
log = []

def checked(args, timeout=120):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    log.append('$ ' + ' '.join(map(str, args)) + '\n' + result.stdout + result.stderr)
    (evidence / 'host-tests.log').write_text('\n'.join(log), encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result

objects = []
for name in ['file_manager_service', 'file_manager_api', 'archive_service', 'archive_browser_service', 'image_preview_service', 'cJSON']:
    obj = build / (name + '.o')
    checked([cxx, *flags, '-c', str(vendor / (name + '.cpp')), '-o', str(obj)])
    objects.append(str(obj))
results = []
for name in ['file_manager_service_test', 'file_manager_api_test']:
    binary = build / name
    linked = objects if name == 'file_manager_api_test' else [str(build / (part + '.o')) for part in ['file_manager_service', 'archive_service']]
    checked([cxx, *flags, str(tests / (name + '.cpp')), *linked, *libraries, '-o', str(binary)])
    result = checked([str(binary)])
    results.append({'test': name, 'exit_code': result.returncode, 'output': result.stdout})
    print('PASS', name)
(evidence / 'host-report.json').write_text(json.dumps({'device_execution': False, 'results': results}, indent=2) + '\n', encoding='utf-8')
