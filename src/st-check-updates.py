#!/usr/bin/env python3
#
# Deprecated. Instead use: src/check-updates.py --api=stex


# For backward compatibility, this script will call the new check-updates.py with the appropriate arguments.
# TODO remove
if __name__ == '__main__':
    import os
    import sys
    import subprocess
    if not sys.executable or not sys.argv or not sys.argv[0].endswith("st-check-updates.py"):
        print("This script has moved. Instead use: src/check-updates.py --api=stex")
        sys.exit(40)
    newfile = os.path.join(os.path.dirname(sys.argv[0]), "check-updates.py")
    result = subprocess.run([sys.executable, newfile, "--api=stex"] + sys.argv[1:], check=False)
    sys.exit(result.returncode)
