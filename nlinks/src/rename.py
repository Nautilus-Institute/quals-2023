import os
import string
import shutil
import hashlib
import json


def main():
    # skip the first 0x8b4 binaries and rename the rest using their MD5 values
    cutoff = 0x8B4
    mapping = {}
    for idx, f in enumerate(os.listdir("./output/")):
        if all(ch in string.digits for ch in f):
            n = int(f)
            if n < cutoff:
                continue
            # rename
            with open(f"./output/{f}", "rb") as f_:
                data = f_.read()
            checksum = hashlib.md5(data).hexdigest()
            assert checksum not in mapping
            mapping[checksum] = n
            shutil.move(f"./output/{f}", f"./output/{checksum}")

    with open("output_name_mapping.json", "w") as f:
        f.write(json.dumps(mapping))


if __name__ == "__main__":
    main()
