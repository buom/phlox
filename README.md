
Phlox is a simple data encryption/decryption service.

## Usage

#### Encrypt
```
$ curl -XPOST -d 'text' http://HOST:PORT/encrypt

WBDTgFTvOf1F8s6cS2mqificKWRujbNHEnHY
```

#### Decrypt
```
$ curl -XPOST -d 'WBDTgFTvOf1F8s6cS2mqificKWRujbNHEnHY' http://HOST:PORT/decrypt

random text
```

#### Hash

```
$ curl -XPOST -d 'random text' http://HOST:PORT/hash

$2a$06$MioXMYRcn0rgdUGxIivzLO2nf2.Dx64PwN3WTDm2qorENqN4ITLx.
```