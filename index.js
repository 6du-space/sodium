(function(){
  var sodium, fs, Hasher, sign, verify, hash;
  sodium = require('sodium-universal');
  fs = require('fs');
  Hasher = (function(){
    Hasher.displayName = 'Hasher';
    var prototype = Hasher.prototype, constructor = Hasher;
    function Hasher(len){
      this.len = len != null
        ? len
        : sodium.crypto_generichash_BYTES;
      this._ = sodium.crypto_generichash_instance(null, this.len);
    }
    Hasher.prototype.update = function(msg){
      return this._.update(msg);
    };
    Hasher.prototype.end = function(){
      var h;
      h = Buffer.allocUnsafe(this.len);
      this._.final(h);
      return h;
    };
    return Hasher;
  }());
  sign = function(sk, msg){
    var signed;
    signed = Buffer.allocUnsafe(sodium.crypto_sign_BYTES + msg.length);
    sodium.crypto_sign(signed, msg, sk);
    return signed;
  };
  verify = function(pk, signed){
    var msg;
    msg = Buffer.allocUnsafe(signed.length - sodium.crypto_sign_BYTES);
    if (sodium.crypto_sign_open(msg, signed, pk)) {
      return msg;
    }
  };
  hash = function(msg, len){
    var h;
    len == null && (len = sodium.crypto_generichash_BYTES);
    h = Buffer.allocUnsafe(len);
    sodium.crypto_generichash(h, msg);
    return h;
  };
  module.exports = {
    Hasher: Hasher,
    sign: sign,
    hash: hash,
    verify: verify,
    pksk: function(){
      var pk, sk, seed;
      pk = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES);
      sk = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES);
      seed = Buffer.allocUnsafe(sodium.crypto_sign_SEEDBYTES);
      sodium.randombytes_buf(seed, sodium.crypto_sign_SEEDBYTES);
      sodium.crypto_sign_seed_keypair(pk, sk, seed);
      return [pk, sk];
    },
    hashSign: function(sk, msg){
      return sign(sk, hash(msg));
    },
    hasher: function(){
      return new Hasher();
    },
    hashPath: function(filepath){
      return new Promise(function(resolve, reject){
        var fd, err, h;
        try {
          fd = fs.createReadStream(filepath);
        } catch (e$) {
          err = e$;
          reject(err);
        }
        h = new Hasher();
        fd.on('data', h.update.bind(h));
        fd.on("end", function(){
          resolve(h.end());
        });
      });
    }
  };
}).call(this);
