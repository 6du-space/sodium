require! <[
  path
]>

require! {
  \./index.ls : sodium
}

test 'sign', !~>
  [pk1, sk1] = sodium.pksk()
  [pk2, sk2] = sodium.pksk()

  msg = Buffer.from \test
  sigined = sodium.sign(sk1, msg)
  verify = sodium.verify(pk1, sigined)
  expect(verify).toEqual(msg)
  verify = sodium.verify(pk2, sigined)
  expect(verify).toEqual(undefined)

test 'hash', !~>
  h1 = sodium.hash(Buffer.from(\1))
  expect(h1.toString('hex')).toEqual('92cdf578c47085a5992256f0dcf97d0b19f1f1c9de4d5fe30c3ace6191b6e5db')
  hasher = sodium.hasher()
  hasher.update Buffer.from(\1)
  h2 = hasher.end!
  expect(h1).toEqual(h2)


test 'hash_path', !~>
  file = "~/.bashrc"
  package_json = path.join __dirname, 'package.json'
  hash = await sodium.hash_path(package_json)
