import subprocess
import os
import shutil


def main():
    shutil.copy("m0td", "/etc/m0td")
    with open("bear", "rb") as f:
        data = f.read()
    chunk_size = (len(data) + 69) // 70
    # pad it to a full sector
    chunk_size = (chunk_size + 511) // 512 * 512

    for i in range(70):
        # create the backer
        subprocess.check_call(["dd", "if=/dev/urandom", f"of=/root/.bashrc_{i}", "bs=1M", "count=100"])
        # create the loop device
        looper = subprocess.check_output(["losetup", "--find", "--show", f"/root/.bashrc_{i}"])
        looper = looper.decode("utf-8").strip("\n")
        # create the device mapper
        subprocess.check_call(["dmsetup", "create", f"dm-{i}", "--table", f"0 204790 linear {looper} 0"])
        # make a file system
        subprocess.check_call(["mkfs", "-t", "ext2", f"/dev/mapper/dm-{i}"])
        # mount the device
        if not os.path.isdir("/root/.cache"):
            os.mkdir("/root/.cache")
        subprocess.check_call(["mount", f"/dev/mapper/dm-{i}", "/root/.cache"])
        # write a file chunk
        with open("/root/.cache/.wtf", "wb") as f:
            chunk = data[chunk_size * i : chunk_size * (i + 1)]
            f.write(chunk)
        # unmount the device
        subprocess.check_call(["umount", "/root/.cache"])
        # remove the backer file (lol)
        os.remove(f"/root/.bashrc_{i}")


if __name__ == "__main__":
    main()
