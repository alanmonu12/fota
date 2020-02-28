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

const functions = require('firebase-functions');
const {
  Storage
} = require('@google-cloud/storage');

const storage = new Storage();

const crypto = require('crypto');

// Upload files at:
// https://console.firebase.google.com/u/0/project/omotion-fota/storage/omotion-fota.appspot.com/files

// Get file at:
// https://europe-west2-omotion-fota.cloudfunctions.net/firmware?model=mk1&key=XXX

// TODO Dummy key. Don't store the keys like this in production!!
const privateKey = '\n-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICXQIBAAKBgQDnetwIUOcVJqpH3KXigeJMaNDtgb8JyE3ReIq//n2TQ7onPpHe\n' +
  'mDntbVXtmjQy+2nGI3c/pgQ/851Fq2HUqxJwRJtjCWTyFXbLRI+Pawxgi7K2H6+M\n' +
  'YVat7FryH1NoIc+hg+8V9RP6qv4BuQh9dAd+hhxVfk/gwqRSc/H9wCYYFwIDAQAB\n' +
  'AoGAZnUrD0NABUyn8kbn5eo3kDqUv4u+U0Ylq6H/SBwM2TIRI22+gxg+C6lpb1Hh\n' +
  '6O7/UoRANBv3pZbe9gd1tfxCnDdB0R9gS1jHlmExy5iiP8kLC/2q+4PVMvshWJKP\n' +
  'eUdvV83T2t/xVtsqGGRs99/Uz3Sa/ZP3mHpg2kUIoOAitAECQQD0TGG42VTi08op\n' +
  'UCI4jctAOG8GKsfd/8xNTRPEs3eiAdDRShkR3yA+KT8IZgCPJT7Aw7SXNkQkbgyw\n' +
  'C28KKn53AkEA8pFL2+ZQBW0SibyzkLIMOpQ27PpzDLkZHGdbtRCDtl+K+ANgHot9\n' +
  '08JfcA7SodeGJdYjYgqs+uZPmPMShD97YQJBAJMeaH80Sl1rI8SrYGBka7FaCupQ\n' +
  '2xpDEJrAvxXm6jWjGEjhcaWElFs65Z2+J7oMuPTHJrslT/YMXBGsYQtjOdMCQASe\n' +
  'f7NQT3XK/e9hiInY2iLDb8hTfJ1haPkBft2T0u5GI39VkR8DyQGfUfHwVlJ+qC9Q\n' +
  'RJw5V9HvUNS4zEF4dAECQQCsIsNpOju0KonLVczZoDdXfx7anzqrzsGmyx6uLEjn\n' +
  '0WawYVlFv6QfTJxluiaiGbseYBgl/LwfXg65AKXZTHbv\n' +
  '-----END RSA PRIVATE KEY-----\n';

const modelKeys = {
  'mk1': Buffer.from('519219269431506468c1f899595afe29', 'hex'),
};

// const fwpkEnc = Buffer.from('454e4343bf000000c0000000000000005ee95b1ec3d56e3a43cfbeeffd51df5f77737cf246dc7f86b1b097a3216434ede44abdb434cb499d06219c79371ca057ccbcef3fb67c004f180bcd71c36c665be869680ef4c39304e04456f015865da15bb21c6374c4c619ddf192bf16ec30ae8a3996b8ebc4cd0ca8e944840b7956414308791ee967b0f6320e6124751b24ec59fac129adf4c02b721329a60fe9d18853e776a1fe1d2ab0fa25ea1ea6e3278d7c4c885f6b4b59abbcb021205475d520e8d310b35fd4b7a1759a2702b8b031501dfff41c026ea51c72c82e2dfa4f895c', 'hex');
let fwpkEnc = null;

exports.firmware = functions
  .region('europe-west2')
  .https
  .onRequest(async (req, res) => {
    const AES_KEY_LEN = 16;
    if (req.query.model && req.query.key && modelKeys[req.query.model]) {
      const requestKey = crypto.privateDecrypt(privateKey, Buffer.from(req.query.key, 'hex'));
      
      if (modelKeys[req.query.model].compare(requestKey, 0, AES_KEY_LEN) == 0) {
        const uniqueKey = requestKey.slice(AES_KEY_LEN);

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', uniqueKey, iv);
        
        // TODO handle error
        if(!fwpkEnc) {
          try {
            let res = await storage
            .bucket('omotion-fota.appspot.com')
            .file(req.query.model + '.fwpk.enc')
            .download();
            console.log(res);
            fwpkEnc = res[0];
          } catch(e) {
            console.error(e);
            res.sendStatus(500);
            return;
          }
        }

        const padding = Buffer.alloc(16 - (fwpkEnc.length & 0xf));
        let fwpkEnc2 = cipher.update(Buffer.concat([fwpkEnc, padding]));
        cipher.final();

        const header = Buffer.alloc(16);
        header.write("ENCC");
        header.writeUInt32LE(fwpkEnc.length, 4);
        header.writeUInt32LE(fwpkEnc.length + fwpkEnc.length, 8);
        header.writeUInt32LE(0, 12);

        res.set('content-type', 'application/octet-stream')
        res.send(Buffer.concat([header, iv, fwpkEnc2]));

      } else {
        res.sendStatus(403);
      }
    } else {
      res.sendStatus(400);
    }
  });

exports.notifyUsers = functions
  .region('europe-west2')
  .storage
  .object()
  .onFinalize(async (object) => {
    console.log('New object ' + object.bucket + ', ' + object.name + ', ' + object.contentType);
    // TODO check file and send push notifications
  });
  