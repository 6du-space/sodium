(function(){
  var sodium, Hasher, sign, verify, hash;
  sodium = require('sodium-universal');
  Hasher = (function(){
    Hasher.displayName = 'Hasher';
    var prototype = Hasher.prototype, constructor = Hasher;
    function Hasher(_){
      this._ = _;
    }
    Hasher.prototype.update = function(msg){
      return this._.update(msg);
    };
    Hasher.prototype.end = function(){
      var h;
      h = Buffer.allocUnsafe(32);
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
  hash = function(msg){
    var h;
    h = Buffer.allocUnsafe(32);
    sodium.crypto_generichash(h, msg);
    return h;
  };
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
    sign: sign,
    verify: verify,
    hash: hash,
    hash_sign: function(sk, msg){
      return sign(sk, hash(msg));
    },
    hasher: function(){
      return new Hasher(sodium.crypto_generichash_instance());
    },
    hash_file: function(filepath){},
    Hasher: Hasher
  };
}).call(this);
