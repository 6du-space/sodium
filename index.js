(function(){
  var sodium;
  sodium = require('sodium-native');
  module.exports = {
    pksk: function(){
      var pk, sk, seed;
      pk = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES);
      sk = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES);
      seed = Buffer.allocUnsafe(sodium.crypto_sign_SEEDBYTES);
      sodium.randombytes_buf(seed, sodium.crypto_sign_SEEDBYTES);
      sodium.crypto_sign_seed_keypair(pk, sk, seed);
      return [pk, sk];
    },
    sign: function(sk, msg){
      var signed;
      signed = Buffer.allocUnsafe(sodium.crypto_sign_BYTES + msg.length);
      sodium.crypto_sign(signed, msg, sk);
      return signed;
    },
    verify: function(pk, signed){
      var msg;
      msg = Buffer.allocUnsafe(signed.length - sodium.crypto_sign_BYTES);
      if (sodium.crypto_sign_open(msg, signed, pk)) {
        return msg;
      }
    }
  };
}).call(this);
