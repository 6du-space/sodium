require! {
  \sodium-universal : sodium
}
require! <[
  fs
]>

class Hasher
  ->
    @_ = sodium.crypto_generichash_instance()

  update:(msg)->
    @_.update msg

  end:->
    h = Buffer.allocUnsafe(32)
    @_.final(h)
    return h

sign = (sk, msg)!~>
  signed = Buffer.allocUnsafe(sodium.crypto_sign_BYTES + msg.length)
  sodium.crypto_sign(signed, msg, sk)
  return signed

verify = (pk, signed)!~>
  msg = Buffer.allocUnsafe(
    signed.length - sodium.crypto_sign_BYTES
  )
  if sodium.crypto_sign_open(msg, signed, pk)
    return msg

hash = (msg)!~>
  h = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(h, msg)
  return h


module.exports = {
  sign
  verify
  hash
  Hasher

  pksk:!~>
    pk = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)
    seed = Buffer.allocUnsafe(sodium.crypto_sign_SEEDBYTES)
    sodium.randombytes_buf(seed, sodium.crypto_sign_SEEDBYTES)
    sodium.crypto_sign_seed_keypair(pk, sk, seed)
    return [pk, sk]

  hash_sign:(sk, msg)~>
    sign(sk, hash(msg))

  hasher:~>
    new Hasher()

  hash_file:(filepath)~>
    new Promise(
      (resolve, reject)!~>
        fd = fs.createReadStream(filepath)
        h = new Hasher()
        fd.on \data , h.update.bind(h) 
        fd.on "end", !~>
            resolve h.end!
    )
}
