require! {
  \./index.ls : sodium
}

test 'sign', ~>
  [pk1, sk1] = sodium.pksk()
  [pk2, sk2] = sodium.pksk()

  msg = Buffer.from \test
  sigined = sodium.sign(sk1, msg)
  verify = sodium.verify(pk1, sigined)
  expect(verify).toEqual(msg)
  verify = sodium.verify(pk2, sigined)
  expect(verify).toEqual(undefined)

test 'hash', ~>
  h1 = sodium.hash(Buffer.from(\1))
  h2 = sodium.hash(Buffer.from(\1))
  expect(h1).toEqual(h2)
  console.log h1
