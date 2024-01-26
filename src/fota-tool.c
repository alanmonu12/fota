// MIT License
//
// Copyright (c) 2020 Andreas Alptun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "fota.h"
#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <assert.h>

#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#define ACTION_NONE             0
#define ACTION_GENERATE_KEY     1
#define ACTION_CREATE_PACKAGE   2
#define ACTION_REQUEST_TOKEN    3
#define ACTION_VERIFY_PACKAGE   4
#define ACTION_INSTALL_FIRMWARE 5

//#define ALIGN16(v) (((v)+15)&(~15))

typedef struct {
  const char* id;
  fota_aes_key_t key;
} model_key_t;

static model_key_t model_keys[] = FOTA_MODEL_KEYS;
static uint8_t hmac_key[] = FOTA_HMAC_KEY;

extern FILE* g_package_file;
extern FILE* g_install_file;

static void print_usage() {
  printf("Usage: fota-tool [-mgfrvil] <arg>\n");
  printf("  -m <model id>      model\n");
  printf("  -g <num keys>      generate unique keys\n");
  printf("  -f <firmware file> create firmware package (requires -m)\n");
  printf("                     add option -2 for installable package\n");
  printf("  -r                 generate request token (requires -m)\n");
  printf("  -v <package file>  verify package\n");
  printf("  -i <package file>  install package\n");
  printf("  -l                 local mode\n\n");
}

static int get_model_key(const char* model_id, fota_aes_key_t* model_key) {
  for(int i=0; i<sizeof(model_keys)/sizeof(model_key_t); i++) {
    if(strcmp(model_keys[i].id, model_id)==0) {
      memcpy(model_key, model_keys[i].key, sizeof(fota_aes_key_t));
      return 1;
    }
  }
  printf("Model not found: %s\n", model_id);
  return 0;
}

static void print_array(FILE* f, const uint8_t* array, uint32_t len) {
  if(array) {
    for(int i=0; i<len; i++) {
      fprintf(f, "%02x", array[i]);
    }
    fprintf(f, "\n");
  }
  else {
    fprintf(f, "null\n");
  }
}

static int nibble(int val) {
  unsigned int v = (val&0xf);
  return v>9 ? v-10+'a' : v+'0';
}

static int generate_unique_keys(const char* model_id, int num_keys) {

  fota_aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return 0;
  }

  setlocale(LC_NUMERIC, "en_US.UTF-8");
  fprintf(stderr, "Generating unique keys for model %s, please wait...\n", model_id);

  fota_aes_key_t generator_key = FOTA_GENERATOR_KEY;

  fota_aes_key_t auth_data[4];
  memcpy(auth_data[0], generator_key, sizeof(fota_aes_key_t));
  memcpy(auth_data[2], model_key, sizeof(fota_aes_key_t));
  memcpy(auth_data[3], generator_key, sizeof(fota_aes_key_t));

  uint8_t auth_hash[32];
  uint8_t hash_zero[32] = {0};

  for(int i=0; i<num_keys; i++) {
    int j = 0;
    while(1) {

      if((j&0xff) == 0) {
        fota_aes_key_t randomKey;
        fotai_generate_random(randomKey, sizeof(fota_aes_key_t));
        memcpy(auth_data[1], randomKey, sizeof(fota_aes_key_t));
      }

      if((j&0xffff) == 0) {
        fprintf(stderr, "\rTried %'d unique id's...", j);
        fflush(stderr);
      }

      auth_data[1][0] = j&0xff;

      mbedtls_sha256_ret((uint8_t*)auth_data, sizeof(auth_data), auth_hash, 0);

      if(memcmp(hash_zero, auth_hash, FOTA_GENERATOR_DIFFICULTY)==0) {
        fprintf(stderr, "Found unique key\n");
        print_array(stdout, auth_data[1], 16);
        print_array(stderr, auth_hash, sizeof(auth_hash));
        break;
      }

      j++;
    }
  }

  return 1;
}

static int generate_random(void* ctx, uint8_t* buf, size_t len) {
  fotai_generate_random(buf, len);
  return 0;
}

static buffer_t* encrypt_buffer(buffer_t* buf, fota_aes_key_t key) {
  fota_aes_iv_t iv;
  fotai_generate_random(iv, sizeof(fota_aes_iv_t));

  buffer_t* enc_buf = buf_alloc(FOTA_STORAGE_PAGE_SIZE + ALIGN16(buf->len));
  buf_write(enc_buf, "ENCC", 4);
  buf_write_uint32(enc_buf, buf->len);
  buf_seekto(enc_buf, 16);
  buf_write(enc_buf, iv, sizeof(fota_aes_iv_t));
  buf_seekto(enc_buf, FOTA_STORAGE_PAGE_SIZE);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int err = mbedtls_aes_setkey_enc(&aes, key, FOTA_AES_KEY_BITSIZE);
  assert(!err);
  err = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, buf->len, iv, buf->data, buf_ptr(enc_buf));
  assert(!err);
  mbedtls_aes_free(&aes);

  return enc_buf;
}

static buffer_t* create_fwpk_enc_package(const char* filename, const char* model_id) {
  assert(FOTA_STORAGE_PAGE_SIZE >= 16 + strlen(model_id)+1);

  int ret = 0;
  int err = 0;

  RsaKey* pRsaKey;
  WC_RNG* rng;

  pRsaKey = malloc(sizeof(RsaKey));
  if (!pRsaKey) {
    printf("RSA_generate_key failed with error\n");
    return NULL;
  }

  rng = malloc(sizeof(rng));
  if (!rng) {
    printf("rng failed with error\n");
    return NULL;
  }

  fota_aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return NULL;
  }

  printf("Creating firmware package for model %s\n", model_id);

  // Load firmware file
  buffer_t* firmware_buf = buf_from_file(filename);
  if(!firmware_buf) {
    printf("Error reading file");
    return NULL;
  }

  // Import private signing key
  //mbedtls_rsa_context private_key;
  //mbedtls_rsa_init(&private_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  ret = wc_InitRsaKey(pRsaKey, NULL);
  if (ret != 0) {
      printf("Init RSA key failed %d\n", ret);
      return NULL;
  }

  ret = wc_InitRng(rng);
  if (ret != 0) {
      printf("Init RNG failed %d\n", ret);
      return NULL;
  }

  printf("Creating firmware package for model %s\n", model_id);

  ret = wc_RsaSetRNG(pRsaKey, rng);

  if (ret != 0) {
      printf("Set RSA RNG failed %d\n", ret);
      return NULL;
  }

  fota_rsa_key_t modulo;
  fotai_get_public_key(modulo, FOTA_PUBLIC_KEY_TYPE_SIGNING);

  byte n[] = {
      0xc7, 0xae, 0x34, 0x95, 0xbc, 0xfb, 0x87, 0xf3, 0xfd, 0x94, 0xf6, 0xd6,
      0x79, 0x13, 0x5b, 0xd7, 0xec, 0x6e, 0x23, 0xdc, 0xa3, 0xbf, 0x8a, 0x9d,
      0x5e, 0x30, 0xcf, 0xa3, 0x68, 0xd3, 0x3b, 0xaa, 0x06, 0xb1, 0x48, 0x66,
      0x63, 0x42, 0xa6, 0xf9, 0xfd, 0x2f, 0x6c, 0xc0, 0x62, 0x83, 0xa8, 0x1c,
      0x33, 0x95, 0x4c, 0x6c, 0x8e, 0x52, 0x62, 0xf0, 0xed, 0x39, 0xc7, 0xe4,
      0xa3, 0x5f, 0xe8, 0x23, 0x20, 0x9e, 0xbf, 0xf6, 0x51, 0x57, 0x63, 0x70,
      0x34, 0x3b, 0xd9, 0xe6, 0x5d, 0xb0, 0x6c, 0xae, 0xf2, 0xdb, 0x25, 0x2d,
      0xe7, 0x62, 0x06, 0xc7, 0x76, 0x61, 0xf2, 0xf3, 0xfb, 0x56, 0x83, 0xac,
      0x29, 0xd9, 0x12, 0x85, 0x3c, 0x50, 0x1d, 0x7b, 0x86, 0xdd, 0xa4, 0x20,
      0xcf, 0xb7, 0xad, 0x94, 0x7c, 0x59, 0x6f, 0x8f, 0x60, 0x2b, 0x5f, 0xe4,
      0x76, 0xd4, 0x1f, 0xe0, 0xda, 0xb7, 0xb1, 0x49
  };

  byte e[] = {0x01, 0x00, 0x01};

  ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), pRsaKey);

  if (ret < 0) {
      printf("Failed to load public rsa key der buffer %d\n", ret);
      return NULL;
  }

  //mbedtls_mpi_read_binary(&private_key.N, modulo, sizeof(fota_rsa_key_t));
  //mbedtls_mpi_read_string(&private_key.D, 16, FOTA_RSA_SIGN_KEY_PRIVATE_EXPONENT);
  //mbedtls_mpi_lset (&private_key.E, OPENSSL_RSA_PUBLIC_EXPONENT);
  //private_key.len = FOTA_RSA_KEY_BITSIZE/8;

  //int err = mbedtls_rsa_complete(&private_key);
  //assert(!err);

  // Create firmware hash
  fota_sha_hash_t firmware_hash;
  err = mbedtls_sha256_ret(firmware_buf->data, firmware_buf->len, firmware_hash, 0);
  assert(!err);

  // Sign the firmware hash
  fota_rsa_key_t firmware_sign;
  err = wc_RsaPSS_Sign((byte*)firmware_hash, sizeof(firmware_hash), (byte*)firmware_sign, sizeof(firmware_sign), WC_HASH_TYPE_SHA256, WC_MGF1SHA256, pRsaKey, rng);
  if (err != 0) {
    printf("wc_RsaPSS_Sign failed %d\n", err);
    return NULL;
  }
  //mbedtls_rsa_rsassa_pss_sign(&private_key, generate_random, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 0, firmware_hash, firmware_sign);
  //assert(!err);
  //mbedtls_rsa_free(&private_key);

  // Create firmware package (.fwpk)
  buffer_t* fwpk_buf = buf_alloc(2*FOTA_STORAGE_PAGE_SIZE + ALIGN16(firmware_buf->len));
  buf_write(fwpk_buf, "FWPK", 4);
  buf_write_uint32(fwpk_buf, firmware_buf->len);
  buf_seekto(fwpk_buf, 16);
  buf_write(fwpk_buf, model_id, strlen(model_id)+1);
  buf_seekto(fwpk_buf, FOTA_STORAGE_PAGE_SIZE);
  buf_write(fwpk_buf, firmware_sign, sizeof(fota_rsa_key_t));
  buf_seekto(fwpk_buf, 2*FOTA_STORAGE_PAGE_SIZE);
  buf_write(fwpk_buf, firmware_buf->data, firmware_buf->len);

  free(firmware_buf);
  //buf_print("fwpk", fwpk_buf);

  // Encrypt package binary (.fwpk.enc)
  buffer_t* fwpk_enc_buf = encrypt_buffer(fwpk_buf, model_key);
  free(fwpk_buf);

  return fwpk_enc_buf;
}

int main(int argc, char* argv[]) {
  int opt;

  int action = ACTION_NONE;
  char* model_id = NULL;
  char* filename = NULL;
  int num_keys = 0;
  int local_mode = 0;
  int create_enc2 = 0;

  while((opt = getopt(argc, argv, ":m:g:f:2rv:i:l")) != -1) {
    switch(opt)
    {
    case 'm':
      model_id = strdup(optarg);
      break;
    case 'g':
      action = ACTION_GENERATE_KEY;
      num_keys = atoi(optarg);
      break;
    case 'f':
      action = ACTION_CREATE_PACKAGE;
      filename = strdup(optarg);
      break;
    case '2':
      create_enc2 = 1;
      break;
    case 'r':
      action = ACTION_REQUEST_TOKEN;
      break;
    case 'v':
      action = ACTION_VERIFY_PACKAGE;
      filename = strdup(optarg);
      break;
    case 'i':
      action = ACTION_INSTALL_FIRMWARE;
      filename = strdup(optarg);
      break;
    case 'l':
      local_mode = 1;
      break;
    case ':':
      printf("Missing argument for option %c\n", optopt);
      break;
    default:
      break;
    }
  }

  wolfSSL_Debugging_ON();

  wolfSSL_Init();


  if(action == ACTION_GENERATE_KEY) {
    if(model_id) {
      generate_unique_keys(model_id, num_keys);
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_CREATE_PACKAGE) {
    if(filename && model_id) {
      buffer_t* fwpk_enc_buf = create_fwpk_enc_package(filename, model_id);

      if(fwpk_enc_buf) {
        // Uncomment the following line to print the fwpk.enc data in hex format
        // buf_print("fwpk.enc", fwpk_enc_buf);

        char* filename_out = malloc(strlen(model_id) + 16);
        strcpy(filename_out, model_id);

        if(create_enc2) {
          strcat(filename_out, ".fwpk.enc2");

          fota_aes_key_t unique_key;
          fotai_get_unique_key(unique_key);

          buffer_t* fwpk_enc2_buf = encrypt_buffer(fwpk_enc_buf, unique_key);

          // Calculate hmac
          fota_sha_hash_t hmac;
          int err = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                    hmac_key,
                                    sizeof(hmac_key),
                                    fwpk_enc2_buf->data,
                                    4*FOTA_STORAGE_PAGE_SIZE,
                                    hmac);
          assert(!err);

          buf_seekto(fwpk_enc2_buf, 32);
          buf_write(fwpk_enc2_buf, hmac, sizeof(fota_sha_hash_t));

          buf_to_file(filename_out, fwpk_enc2_buf);

          free(fwpk_enc2_buf);
        }
        else {
          strcat(filename_out, ".fwpk.enc");
          buf_to_file(filename_out, fwpk_enc_buf);

          if(!local_mode) {
            printf("Upload at https://console.firebase.google.com/u/0/project/%s/storage/%s.appspot.com/files\n",
                   FOTA_FIREBASE_PROJECT, FOTA_FIREBASE_PROJECT);
          }
        }

        free(fwpk_enc_buf);
      }
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_REQUEST_TOKEN) {
    fota_token_t token;
    int err = fota_request_token(token);
    assert(err==FOTA_NO_ERROR);

    char token_hex[2*sizeof(fota_token_t)+1];
    char* p = token_hex;
    for(int i=0; i<sizeof(fota_token_t); i++) {
      int b = token[i];
      *p++ = nibble(b>>4);
      *p++ = nibble(b);
    }
    *p = '\0';

    const char* url[3] = { "https://europe-west2-", FOTA_FIREBASE_PROJECT, ".cloudfunctions.net" };
    if(local_mode) {
      url[0] = "http://localhost:5001/";
      url[2] = "/europe-west2";
    }

    printf("curl %s%s%s/firmware?model=%s&token=%s -v --output %s.fwpk.enc2\n",
           url[0], url[1], url[2],
           fota_model_id(), token_hex, fota_model_id());
  }
  else if(action == ACTION_VERIFY_PACKAGE) {

    g_package_file = fopen(filename, "rb");
    if(!g_package_file) {
      printf("Package file not found: %s\n", filename);
    }
    else {
      fota_sha_hash_t firmware_hash;
      int err = fota_verify_package(firmware_hash);
      if(err==FOTA_NO_ERROR) {
        printf("Firmware is verified, proceed to installing the update!\n");
        print_array(stdout, firmware_hash, sizeof(fota_sha_hash_t));
      }
      else {
        printf("Firmware did not pass verification! (error=%d)\n", err);
      }

      fclose(g_package_file);
      g_package_file = NULL;
    }
  }
  else if(action == ACTION_INSTALL_FIRMWARE) {

    char* filename_install = malloc(strlen(filename) + 16);
    strcpy(filename_install, filename);
    strcat(filename_install, ".inst");

    g_package_file = fopen(filename, "rb");
    if(!g_package_file) {
      printf("Package file not found: %s\n", filename);
    }
    else {
      g_install_file = fopen(filename_install, "wb");
      assert(g_install_file);
      
      int err = fota_install_package();
      if(err==FOTA_NO_ERROR) {
        printf("Firmware is installed to file %s!\n", filename_install);
      }
      else {
        printf("Firmware installation failed! (error=%d)\n", err);
      }
      
      fclose(g_package_file);
      fclose(g_install_file);
      
      g_package_file = NULL;
      g_install_file = NULL;
    }

    free(filename_install);
  }
  else {
    print_usage();
  }

  if(filename) free(filename);
  if(model_id) free(model_id);
}
