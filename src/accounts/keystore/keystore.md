# Keystore
Scrypt와 Aes를 활용하여 Private Key 관리

- 예제

```
{
    "version": 3,
    "id": "4c07993f-ded2-405a-b83d-3b627eebe5cd",
    "address": "e449efddf8c9b174bbd40a0e0e1902d6eee72068",
    "Crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {
          "iv": "7d416faf14c88bb124486f6cd851fa88"
        },
        "ciphertext":"e99f6d0e37f33124ee3020fad01363d9d7500efce
                      913aede8a8119229b7a5f2e",
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32,
            "salt": "c47f395c9031233453168f01b5a9999a06ec97c829
                     a395ecd16e1ad37102ec7f",
            "n": 8192,
            "r": 8,
            "p": 1
        },
        "mac": "82078437ee94331c69125eef4001ff4b78b481e909a6
                2a9ac25aa916237b70be"
    }
}
```

## 각 요소 설명
- version : 키스토어 파일 포맷 버전. 현재 3
- id : 키스토어에 대한 고유 식별자(UUID).
- address : 이더리움 주소. public key
- Crypto : 개인키 암호화를 위한 요소들
  - cipher : 암호화 알고리즘. aes-128-ctr 사용. 양방향 암호화 알고리즘. AES(Advanced Encryption Standard) 128 비트를 사용하는 카운터 모드(CTR)
  - cipherparams : 암호화 알고리즘의 파라미터. iv(초기화벡터)가 포함되며 암호화 과정에서 사용.
    - iv : 암호화 시 사용되는 초기화 벡터. 랜덤 값.
  - ciphertext : 암호화된 개인키. 이 값을 통해 복호화.
  - kdf : 키 파생함수. scrypt 사용. 단방향 암호화 알고리즘
  - kdfparams : scrypt를 사용하기 위한 키 파생 함수의 파라미터들. 
    - dklen : 파생된 키의 길이. 
    - salt : 키 파생 과정에서 사용되는 무작위 데이터. 랜덤 값 사용.
    - n, r, p : scrypt의 알고리즘. 메모리와 CPU 사용량을 조절하여 암호화의 안정성 결정
  - mac : 메시지 인증 코드(Message Authentication Code)로, 암호화된 데이터의 무결성을 검증하는 데 사용. 이 값은 비밀번호를 이용해 생성된 파생 키와 ciphertext를 합쳐서 keccak-256 해시 함수로 해싱하여 생성

## 동작
1. password를 입력 받는다.
2. kdfparams(dklen,n,r,p,salt)와 password를 scrypt로 암호화한다. 파생된 키를 aes-128-ctr에서 사용할 것이다.
3. private key + iv를 scrypt에서 파생된 키를 사용하여 AES로 암호화한다.
4. 암호화된 text(ciphertext)를 반환한다. 
5. 복호화를 할 때는 ..?



## 상수로 정해져야 할 것
- `version` : `u8` = 3
- `cipher` : `&str` = "aes-128-ctr"
- `kdf` : `&str`?? = "scrypt"
- `dklen` : `u8` = 32
- `n` : `u8` = 13
- `r` : `u32` = 8
- `p` : `u32` = 1


## 각 요소 type 및 value 
- `version` 
  - type - u8
  - value - 3
- `id`
  - type - UUID
  - value - UUID v4
- `address`
  - type - hex? 
  - value - public key
- `cipher`
  - type - &str
  - value - "aes-128-ctr"
- `iv`
  - type - vec? bytes? hex?
  - value - rand::thread_rng() -> bytes
- `ciphertext`
  - type - 
  - value - aes(private_key). private key를 aes로 암호화한 값.
- `kdf`
  - type - &str
  - value - "scrypt"
- `dklen`
  - type - u8
  - value - 32
- `n`
  - type - u8
  - value - 13  // 2^13 = 8192
- `r`
  - type - u32
  - value - 8
- `p`
  - type - u32
  - value - 1
- `mac`
  - type - vec? bytes? hex?
  - value - keccak256(Scrypt(private_key)+ciphertext)
