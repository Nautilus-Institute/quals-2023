OBJS = firmware.o syscalls.o
STAGE2_OBJS = stage2.o syscalls.o
GOOD_OBJS = good_firmware.o syscalls.o
ELF_TARGET = firmware.elf
STAGE2_ELF_TARGET = stage2.elf
GOOD_ELF_TARGET = good_firmware.elf
OUT_BLOB = firmware.text
OUT_LOADER = loader.text
OUT_STAGE2 = stage2.text
GOOD_OUT_BLOB = good_firmware.text
GOOD_OUT_BLOB_LZ4 = good_blob.raw.lz4
STRING_BLOB = strings.data
OBJCOPY ?= objcopy
CFLAGS ?= -fno-stack-protector -fcf-protection=none
XXD ?= xxd

show: build $(GOOD_OUT_BLOB_LZ4)
	cat $(OUT_BLOB) $(GOOD_OUT_BLOB_LZ4) > $(OUT_LOADER)
	python3 blobify.py $(OUT_LOADER)

$(GOOD_OUT_BLOB_LZ4): $(GOOD_OUT_BLOB) $(STRING_BLOB)
	python3 blobify.py $(GOOD_OUT_BLOB) $(STRING_BLOB) trusted_firmware
	./blz4/build/blz4 trusted_firmware.raw $(GOOD_OUT_BLOB_LZ4)

$(GOOD_OUT_BLOB): $(GOOD_ELF_TARGET)
	$(OBJCOPY) -O binary --only-section=.text $(GOOD_ELF_TARGET) $(GOOD_OUT_BLOB)
	$(OBJCOPY) -O binary --only-section=.rodata $(GOOD_ELF_TARGET) $(STRING_BLOB)


build: exe_x $(GOOD_ELF_TARGET) stage2
	$(OBJCOPY) -O binary --only-section=.text $(ELF_TARGET) $(OUT_BLOB)
	$(OBJCOPY) -O binary --only-section=.text $(STAGE2_ELF_TARGET) $(OUT_STAGE2)

exe_x: $(OBJS)
	$(CC) -o $(ELF_TARGET) -nostdlib -fPIC $^

stage2: $(STAGE2_OBJS)
	$(CC) -o $(STAGE2_ELF_TARGET) -nostdlib -fPIC $^

$(GOOD_ELF_TARGET): $(GOOD_OBJS)
	$(CC) -o $(GOOD_ELF_TARGET) -nostdlib -fPIC -Tdata 0x2000 $^

clean:
	rm $(OBJS) $(ELF_TARGET) $(OUT_BLOB)
