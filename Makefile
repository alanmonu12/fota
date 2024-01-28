CC=gcc
CDEBUGFLAGS=-g -D_GLIBCXX_DEBUG -DDEBUG
CFLAGS=-Wall -I/usr/local/include -L/usr/local/lib -lm -Isrc -Imbed-crypto/include -I/usr/local/lib/include -DMBEDTLS_CONFIG_FILE=\"mbedtls-config.h\"
CFLAGS+= $(CDEBUGFLAGS)
LDFLAGS=-lwolfssl -lwolfssl

SRC=src/fota.c

LIB=mbed-crypto/library/rsa.c \
  mbed-crypto/library/bignum.c \
  mbed-crypto/library/md.c \
  mbed-crypto/library/platform_util.c \
  mbed-crypto/library/rsa_internal.c \
  mbed-crypto/library/sha256.c \
  mbed-crypto/library/aes.c

ifeq ($(findstring client,$(1)),client)
  SRC+=src/fota-client.c
  CFLAGS+=-Os -m32 -DFOTA_CLIENT -DBUFFER_NO_STDIO
  OUTPUT=fota-client
else
  SRC+=src/buffer.c src/fota-tool.c src/fota-integration.c
  CFLAGS+=-DFOTA_TOOL
  ifeq ($(2),release)
    CFLAGS+=-O3
  else
    CFLAGS+=-O0
  endif
  OUTPUT=fota-tool
endif

all: $(OUTPUT)

$(OUTPUT): $(SRC)
	$(CC) $(CFLAGS) $^ $(LIB) -o $@ $(LDFLAGS)

ifeq ($(1),client-stripped)
  strip $(OUTPUT)
  @echo -n "Size: "
  @stat -c "%s" $(OUTPUT)
endif

clean:
	@rm -f $(OUTPUT)
