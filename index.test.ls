require! {
  \./index.ls : sodium
}

test 'sign', ~>
  [pk1, sk1] = sodium.pksk()
  [pk2, sk2] = sodium.pksk()

  msg = Buffer.from \test
  sigined = sodium.sign(sk1, msg)
  verify = sodium.verify(pk1, sigined)
  console.log verify, msg
  expect(verify).toEqual(msg)


