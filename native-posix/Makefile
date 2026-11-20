API ?= 24

# Auto-detect NDK (same rules as ../native-pct/Makefile).
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(or $(ANDROID_NDK_HOME),$(NDK_ROOT_ENV),D:/android-ndk-r27d))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  EXT := .cmd
  STRIP_EXT := .exe
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),/opt/android-ndk-r27d)
  UNAME_S := $(shell uname -s)
  PREBUILT := $(if $(filter Darwin,$(UNAME_S)),darwin-x86_64,linux-x86_64)
  EXT :=
  STRIP_EXT :=
endif

NDK_BIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin
CC := $(NDK_BIN)/aarch64-linux-android$(API)-clang$(EXT)
STRIP := $(NDK_BIN)/llvm-strip$(STRIP_EXT)

BUILD_DIR ?= ../build/posix
OUT := $(BUILD_DIR)

# Single file, no headers of its own. The offsets and the exploit geometry are not
# baked in: they arrive as a HOCON profile at run time, so one binary serves every
# kernel >= 5.7 that the Profile tab has a parsed profile for.
CFLAGS := -O2 -fno-stack-protector
LDFLAGS := -Wl,-z,max-page-size=16384

.PHONY: all payload clean

all: payload

payload: $(OUT)/libcve98260.so

$(OUT)/libcve98260.so: cve98260.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) cve98260.c -o $@ $(LDFLAGS)
	$(STRIP) $@

clean:
	rm -rf $(OUT)
