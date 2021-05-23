# HOTP-TOTP
Go implementation of one time password generators
# License
This project is licensed under the terms of the simplified BSD license.
# How to use
Basic example:
```go
pass := htOTP.Password{
  "Your_secret",
  0,
  10,
  30 * time.Second,
  time.Now(),
  sha1.New,
}
fmt.Println(pass.HOTP())
fmt.Println(pass.TOTP())
```

# Why
Recently I was faced with a challenge to generate 10 digit TOTP password with sha512 hashing and pass verification while performing POST request. I tried using other OTP implementations but none of them worked. None apart of this Python OTP program: https://github.com/hugohue/TOTP-10-digits-/blob/master/src/totp.py. So i decided to write a program in Go that will give the same results as this Python one. The main thing (atleast I think so) that is different in my version of OTP in comparison to other Go OTP generators is passing the counter in binary.Write as an uint64.

