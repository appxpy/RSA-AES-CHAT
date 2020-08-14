from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA

privatekey = RSA.generate(1024)
publickey = privatekey.publickey()
message = 'To be sigfffffwqfareggddgkuajhrlueiqhrequihlgrequhilqgriulhgreiuhlgreiuhrgqhrgqeuiihughugraeh;e;haer;hrgh;egrahi;oeqrearegagregergreageageagergreegrakjsdhvb`,aehiufgkuyfuyFEWtkdugkywfgyuwefgylufwegkuyscfguyefwkugEFguwyUKUYAFufkyaUFYAUVned'.encode('utf-8')
h = SHA.new(message)
signer = PKCS1_v1_5.new(privatekey)
signature = signer.sign(h)
h = SHA.new(message)
verifier = PKCS1_v1_5.new(publickey)
if verifier.verify(h, signature):
   print("The signature is authentic.")
else:
   print("The signature is not authentic.")