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

#ifndef FOTA_CONFIG_H
#define FOTA_CONFIG_H

#warning "Sample config! Copy fota-config-sample.h to fota-config.h and use project specific keys"

// System config
// Page size of the memory on which the downloaded firmware package is stored, usually an external flash chip
#define FOTA_STORAGE_PAGE_SIZE 256
// Page size of the memory where the firmware will be installed, usually internal flash
#define FOTA_INSTALL_PAGE_SIZE 512

// Crypto config
#define FOTA_RSA_KEY_BITSIZE 1024
#define FOTA_AES_KEY_BITSIZE 128
#define FOTA_HMAC_KEY {0x8f,0x95,0xca,0x9f,0xbc,0xda,0x99,0xfe,0x8f,0xd5,0x82,0x9e,0xa2,0x0f,0xab,0xae,0x6d,0x77,0x5b,0x0e,0xc2,0x2a,0xa9,0xf1,0xb3,0xad,0xe4,0x3b,0x59,0x84,0x40,0xf5,0x4f,0x96,0xb1,0x30,0x2b,0xdf,0x34,0x2d,0x52,0x15,0x33,0x05,0xf6,0x01,0x27,0x9d,0x3d,0x7a,0xa8,0xe8,0x44,0xf1,0x30,0xf0,0x0d,0x20,0xb5,0xdf,0xa0,0xdc,0x17,0xe2}
#define FOTA_RSA_OAEP_LABEL {0x84,0x60,0x56,0xfd,0xcd,0x92,0x04,0x38,0x34,0x1e,0x7c,0x84,0x08,0xc3,0x52,0x2a,0x0f,0x4e,0xe7,0x77,0x8e,0xff,0xb0,0x91,0x60,0x34,0x6d,0xcb,0x65,0x01,0x02,0x9d}

// Models
#define FOTA_MODEL_ID_MK1 "mk1"
#define FOTA_MODEL_KEY_MK1 {0x51,0x92,0x19,0x26,0x94,0x31,0x50,0x64,0x68,0xc1,0xf8,0x99,0x59,0x5a,0xfe,0x29}
#define FOTA_MODEL_KEYS {{FOTA_MODEL_ID_MK1, FOTA_MODEL_KEY_MK1}}

// Generator key
#ifdef FOTA_TOOL
#define FOTA_GENERATOR_KEY {0x33,0x71,0xae,0x3b,0xdf,0xc3,0x8d,0x0c,0x11,0xd4,0x9e,0x22,0x3a,0x26,0x55,0x47}
#define FOTA_GENERATOR_DIFFICULTY 3
#endif

// Private key
#ifdef FOTA_TOOL
#define FOTA_RSA_SIGN_KEY_PRIVATE_EXPONENT "9f51ad7f33b3f57b857e8f9bfc2aa803160fa2e96e756b61b83f75cc49dd1023cf07305f111fa31e9f1671cce64d699a66c5de9e56c8014d7dd9b65604cc86e7e7388ea0623fe9911a38bdd448e86fe061dc67f5a8dbeda8f14af50c845fd254c03167379a8ccc9c43365e992dbe8af1e3ec34e8c8a502312395ffe2ce273a21"
#endif

// NOTE:
// Private encryption key pem and generator key+difficulty must also be added to firebase/functions/index.js

// Firebase project
#ifdef FOTA_TOOL
#define FOTA_FIREBASE_PROJECT "xxx-fota"
#endif

#endif //FOTA_CONFIG_H
