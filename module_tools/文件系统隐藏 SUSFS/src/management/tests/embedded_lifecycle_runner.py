"""Host subprocess lifecycle test, including first-install settings; no Android contact."""
import argparse
from pathlib import Path
import subprocess
parser=argparse.ArgumentParser()
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
repo=Path(__file__).resolve().parents[2]
out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
vendor=repo/'module/vendor/file_manager'
subject=out/'subject.o'
subprocess.run(['cc','-std=c11','-c',str(repo/'kernel/skp_subject_policy.c'),'-o',str(subject)],check=True)
sources=['tests/embedded_lifecycle_test.cpp','embedded.cpp','service.cpp','backend.cpp','config.cpp','config_transfer.cpp','inventory.cpp','common.cpp']
binary=out/'embedded-lifecycle'
subprocess.run(['c++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wpedantic','-pthread','-I',str(vendor),
    *[str(repo/'management'/s) for s in sources],str(vendor/'cJSON.cpp'),str(subject),'-o',str(binary)],check=True)
result=subprocess.run([str(binary)],text=True,capture_output=True,timeout=45)
(out/'embedded-lifecycle.txt').write_text(result.stdout+result.stderr)
print(result.stdout,end='')
if result.returncode:print(result.stderr)
raise SystemExit(result.returncode)
