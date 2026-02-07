## Password reset path with correct OTP

1. First some sort of hidden captcha request is made:

request:
```http
POST /captcha.htm HTTP/1.1
Host: iantcaptchaqk.alipay.com
Content-Length: 1033
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
Sec-Ch-Ua-Mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/javascript, text/html, application/xml, text/xml, */*
Content-Type: application/json
Origin: https://global.alipay.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://global.alipay.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"type":"silence","bizNo":"d963d8ab951aaec097694819e30e1dbdmjJ13KQ1iB63BD3fyddDySWhLRBFa77W","data":"vVDnHFx6FDYWxKFAJ96q9UOuWDSSxqnJGzHBfMFl2pIqUtk4Dh.KXy5sJGnNzzDoTExANCwW4jfxXQ.IcBN6hwCCIf.lw1TzRVzClNukrYLRJ3letdPV7piMusZ0rWCT6vu6DKKPG1MV53qjbhAiEOy2FXpeJsIwdR3wdthhwr2Lp5jBvyQ1Ynstx7Xe95ijOqMP4qlw1779xaeMYNcSGJJHLM4cQiAVYn6mkwGw9Vj25C.DXFtzQrG9bY_ZeOAaAkMp0xdWFpkXG7AW3.glTfoLT2KwIBr.MdNjbuh8BpLQeEDPjzOq5y1n.Gw6z8flChnuJu5KIgsCdaxGjB05.nhCXGzW0_KwL7KoRUPWeMAKl4HF_ONiw26ofzCXjKgEWAXq4TDmRkYkJcCm7fuND0daH6Z8WRp_EIFXyMXuxCYBonU7ETQbY5xvWdl0zP9mEQX5HXcetETgSGmgEVOQCQeBaqqkN1gTFj3EbEzMvLvIuC84X20zdElLJqnrP5acSA2rLudjblw6ofbjw.oyqxj5URyfL3nR2i6xiyKKomUOPR4xCHSfBD2YIceZ7m2TY5.tyuofzHhLsrvES3ECXl5uecPz6ZUnn1mRu_FHALCQfO5wrYjpksTSafLkhfhNN.UB3gQKkmk56oMoDC890_rYNMCnPJeQzgg1tw4yIuND4AGBQezxcI54dEBj1kIsl.DqQAmC.ixvL4FD19ePiCWeSxS2yGlOwEMkWztv3r.hVA.HCk51eiU_JaBLdaQdj18PGzo6gKtn9LFR6.uqLUj0QRJh1vTyGTAw5_BMUik7LiYAqCHeLcMdUjJiJNP5VChwBMBHSvPY7JruDTb1Tt5IsCKeWrXDJuchvFfY3pG","appid":"imhome_resetLoginPwd_qk","scene":"DO_NOTHING"}
```

response:
```http
HTTP/2 200 OK
Server: Spanner
Date: Sat, 07 Feb 2026 11:25:38 GMT
Content-Type: application/json;charset=UTF-8
Vary: Accept-Encoding
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: https://global.alipay.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
Set-Cookie: ALIPAYINTLJSESSIONID=GZ00562FE445A8524C2D9409436171D3A06BiantcaptchaGZ00; Domain=.alipay.net; Path=/
Set-Cookie: ctoken=yzlkHiuyGLVIzYVC; Domain=.alipay.net; Path=/
Set-Cookie: JSESSIONID=GZ00562FE445A8524C2D9409436171D3A06BiantcaptchaGZ00; Path=; Secure; HttpOnly
Set-Cookie: spanner=TqgYLbwWCCnk4aE2sOwNn4JaNc1wMQbb;path=/;secure;
Via: ispanner-internet-qkgz00f-8.sg52y[200]
Origin-Agent-Cluster: ?0

{"data":{"result":"pass","extra":{"token":"2b76da92a0f14b14ab4e1487e978b0a4d2698d89a807477096a41f96626a980b_QK"}},"message":"","success":true}
```

This gets us `token`

2. Some sort of checkEmail request that send the `token` + `email` + `bizNo`

request:
```http
POST /merchant/proxyapi/member/checkEmail.json?_route=QK&ctoken=lryb1T619p2sp8uG HTTP/2
Host: global.alipay.com
Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; tntInstId=ALIPW3SG; intl_locale=en_US; session.cookieNameId=ALIPAYINTLJSESSIONID; LOGON_FLAG=true; CROSS_TOKEN_REGION=5; registered="0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja"; cna=WuwNIrbXvmgCASXS+B42LsSs; _region=QK; ALIPAYJSESSIONID=GZ00wRpBaCy75qdaPSgmZ98jgrZnoBglobalprodGZ00; ALIPAYINTLJSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; ctoken=lryb1T619p2sp8uG; sofaId=218425b917704628178841494ea712; x-hng=lang=en-US; _CHIPS-x-hng=lang=en-US; JSESSIONID=E2E178A412A808C95009047CBAE80CD8; spanner=Ty2ygMGKe1bk4aE2sOwNn34JIlDI+y1g; tfstk=goQnWF24gM-BtUkaoY8QfIG_o5r9deTWTT3JeUpzbdJ1pULLVUVkITYR9UEQzGXPCHpF9WtyE96k24LeyTxPGTYJLkwBETfAB4pUNeKrEtCVE3NBeLJle_SL6rUAO6TWzU2YkrdThhSlKv-e47RwNQV9TxSJbp8Wz-eta1YOUU6hIWxyz1PMwQnrLTJeb5AXZUue42oZQdOyzU-r8fuwwQmrz4Rzs1J6aUJPUUPM7dOyzLWyzbJzLp7PJNyDBfDqLI-VSBxH314sz4bikHJVTd0z3NA3lK5eI4uJ35Mf11fLKq19RZBDM9UZ-tfPGg-GrAyDFNfN8g5sK8R149LwpErEseQCTi-Pu8iPneXk0w-iaq5CTLYM_ZP-cdQMpT7HbS3D2F7v0eSTfJKJ-IXPR9cozt5OMwt1r-DwFMdX7Qb7g0vk4gSmbmyDo4OawNoSVHR6sKesy-Wh1u04i5VimLte1BJAy5mTyHR6_pVgsmfkYCOnY; isg=BD8_wWCIavG8mm7sP2fA0_C4zhPJJJPGvxXEPNEM2-414F5i2fbrFyz2JqgeuGs-
Content-Length: 256
Sec-Ch-Ua-Platform: "Windows"
Ctoken: lryb1T619p2sp8uG
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: application/json
Content-Type: application/json;charset=UTF-8
Bx-V: 2.5.36
Origin: https://global.alipay.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://global.alipay.com/merchant/portal/account/forget?_route=QK
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"email":"0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja","antCaptchaToken":"2b76da92a0f14b14ab4e1487e978b0a4d2698d89a807477096a41f96626a980b_QK","bizNo":"d963d8ab951aaec097694819e30e1dbdmjJ13KQ1iB63BD3fyddDySWhLRBFa77W","rdsAppId":"imhome_resetLoginPwd_qk"}
```

response:
```http
HTTP/2 200 OK
Server: nginx/1.6.2
Date: Sat, 07 Feb 2026 11:25:38 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 42
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: https://global.alipay.com
Access-Control-Allow-Credentials: true
Itraceid: 21b0d51d17704635383844879ebd77
Content-Language: en-US
Set-Cookie: JSESSIONID=9629D10C2B4A066EDB87679D32B5ABB4; Path=/; HttpOnly
Set-Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; Path=; Secure; HttpOnly
Set-Cookie: spanner=qXKlOxVSP1qIpIYlv1uhJ233XAX6Rbfx4EJoL7C0n0A=;path=/;secure;
Via: ispanner-internet-qkgz00f-8.sg52y[200]
Origin-Agent-Cluster: ?0

{"data":{"validated":true},"success":true}
```

3. A `consultRisk` request that gets us the `verifyId` and `securityId` towards getting the OTP code:

request:
```http
POST /merchant/proxyapi/member/consultRisk.json?_route=QK&ctoken=lryb1T619p2sp8uG HTTP/2
Host: global.alipay.com
Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; tntInstId=ALIPW3SG; intl_locale=en_US; session.cookieNameId=ALIPAYINTLJSESSIONID; LOGON_FLAG=true; CROSS_TOKEN_REGION=5; registered="0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja"; cna=WuwNIrbXvmgCASXS+B42LsSs; _region=QK; ALIPAYJSESSIONID=GZ00wRpBaCy75qdaPSgmZ98jgrZnoBglobalprodGZ00; ALIPAYINTLJSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; ctoken=lryb1T619p2sp8uG; sofaId=218425b917704628178841494ea712; x-hng=lang=en-US; _CHIPS-x-hng=lang=en-US; JSESSIONID=9629D10C2B4A066EDB87679D32B5ABB4; spanner=qXKlOxVSP1qIpIYlv1uhJ233XAX6Rbfx4EJoL7C0n0A=; tfstk=gA3sksYpyOX_srd9HORFFNLygazjfB8yksNxZjQNMPUOhIMK3C4qMhAXljDf_opg7qMILYNq7q-icSeKMRP43hAjdxkm7RPZgSHIMYgNbooaMEeLMtza_m5ixYlR7V-guZagorpyUU8ysf40kZ4H5lXGpSP2uZUYXP4piHWM5U8rsfFBR5vwzcW0R7PYHrETDMCLKSNYk-QvOJFbZiBtHrdBOSNlHGETXMFLs7zYHxUvOXe3MrFtHrdI9JVxaUxQ9hwE1I1uLi1dNoGTdZQxWhq_FfIVlZgQ1lgx6JGET2N_f8rXIWkSWvlx7VqHxMzmT0MjDYpFbRn7NvZrfL_sFAVxdPuJihq3DqgbtDvfc8ix_0mYACLtOPw_D2kd6iasDA0bjc1DZXUtK02uXHv3OVuzc8qCpdhEOREScAJhkRoS9vZr897zy0DIluUR4-QzFrFNc6ZllWwyOBscmPoqLKIZwGk8XWVhaBOC4iXlkZEkOBsVHlF3tCdBOgjf.; isg=BAQE9n_RMXC7BIW9MM5L8peR1YL2HSiH-CzvTR6lkE-SSaUTRi8wFqvvjfmR0WDf
Content-Length: 31
Sec-Ch-Ua-Platform: "Windows"
Ctoken: lryb1T619p2sp8uG
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: application/json
Content-Type: application/json;charset=UTF-8
Bx-V: 2.5.36
Origin: https://global.alipay.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://global.alipay.com/merchant/portal/account/security/0xkujen-ywh-fdd598ecef7c9f7b%40yeswehack.ninja?_route=QK&featureCode=findLogonPassword
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"scene":"FIND_LOGON_PASSWORD"}
```

response:
```http
HTTP/2 200 OK
Server: nginx/1.6.2
Date: Sat, 07 Feb 2026 11:25:41 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 190
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: https://global.alipay.com
Access-Control-Allow-Credentials: true
Itraceid: 21b0d51d17704635410574889ebd77
Content-Language: en-US
Set-Cookie: JSESSIONID=A406B1DA587D87A25B6446D536C0C8EE; Path=/; HttpOnly
Set-Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; Path=; Secure; HttpOnly
Set-Cookie: spanner=qXKlOxVSP1qIpIYlv1uhJ233XAX6Rbfx4EJoL7C0n0A=;path=/;secure;
Via: ispanner-internet-qkgz00f-2.sg52y[200]
Origin-Agent-Cluster: ?0

{"data":{"verifyId":"628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site","verifyProductCode":"otpEmail","securityId":"628c7e947ea536ee4f2550bc6f08ef9a","riskStatus":"VERIFICATION"},"success":true}
```

4. Now initiate the final OTP process by sending the `verifyId`:

request:
```http
GET /api/mic/view?productCode=otpEmail&verifyId=628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site&_output_charset=utf-8&_input_charset=utf-8 HTTP/1.1
Host: ifcidentitycloudqk.alipay.com
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://render.antfin.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://render.antfin.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive




```

response:
```http
HTTP/2 200 OK
Server: Spanner
Date: Sat, 07 Feb 2026 11:25:44 GMT
Content-Type: application/json;charset=utf-8
Vary: Accept-Encoding
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Set-Cookie: spanner=88NBLP+bmoUINfHresoopn2fYsRoGVaOXt2T4qEYgj0=;path=/;secure;
Via: ispanner-prod-2.sg113y[200]
Origin-Agent-Cluster: ?0

{"traceId":"21840f3a17704635439712719e69a2","verifyId":"628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site","method":"otpEmail","renderData":{"HAS_OTHERS":false,"VALIDATECODE_SEND_TIME_LIMIT":"The number of sending verification code has reached the maximum","code":"VALIDATECODE_SEND_SUCCESS","page_title":"ID Verification","SYSTEM_ERROR":"Server is busy, please try again later.","mobile_no":"0xk***@yeswehack.ninja","source":"ECPAY","USER_LOCK":"Your account has been locked, please try again in 3 hours","templateId":"100001","foot_tip":"Change Method","form_input_tip_low":"Resend","USER_LOCK_LEFT_TIME_4":"Verification failed, four chances left to be locked","USER_LOCK_LEFT_TIME_2":"Verification failed, two chances left to be locked","MSG_SEND_TIMES_LIMIT":"Your verification code request is too frequent, please try again later","USER_LOCK_LEFT_TIME_3":"Verification failed, three chances remaining or your account will be locked","PROCESS":"Verification is being processed.","VALIDATECODE_SEND_FAILURE":"Failed to send OTP on registered email.","VALIDATECODE_SEND_SUCCESS":"OTP sent successfully on registered email.","USER_LOCK_LEFT_TIME_1":"Verification failed, one chance left to be locked","SUCCESS":"Success","VALIDATE_LOCKED":"OTP verification option by email is disabled for three hours, please try again later.","VERIFY_ERROR":"Verification failed, please try again.","PROCESS_FAIL":"Server is busy, please try again later.","SERVICE_CODE_PLACE_HOLDER_ACTION":"verify","message":"OTP sent successfully on registered email.","form_button":"Confirm","form_title":"Enter code sent to ","VERIFY_ERROR_MSG_2":"Incorrect OTP entered, please try again (2 attempts left)","VERIFY_ERROR_MSG_1":"Incorrect OTP entered, please try again (1 attempt left)","PASS":"Verification is successful.","VALIDATE_TIMES_LIMIT":"OTP verification by email, has failed too many times, please try again later.","body_title":"Verification","901":"Customer doesn't exist in our record.","ACCOUNT_ILLEGAL":"User account is invalid.","head_title":"Email Verification"},"tokenId":"877570f51a485eb9f91384d08cb0b445","success":true,"resultCode":"SUCCESS","resultMessage":"OTP sent successfully on registered email."}
```


5. Now final request after receiving the otp code on email:

request:
```http
GET /api/mic/verify?data=862884&productCode=otpEmail&verifyId=628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site&_output_charset=utf-8&_input_charset=utf-8 HTTP/2
Host: ifcidentitycloudqk.alipay.com
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://render.antfin.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://render.antfin.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i



```

response:
```http
HTTP/2 200 OK
Server: Spanner
Date: Sat, 07 Feb 2026 11:26:08 GMT
Content-Type: application/json;charset=utf-8
Content-Length: 312
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Set-Cookie: spanner=U6MPdvbD5rx4CNCRcDh5X26QTZwjOfx+Xt2T4qEYgj0=;path=/;secure;
Via: ispanner-prod-15.sg113y[200]
Origin-Agent-Cluster: ?0

{"traceId":"2184086317704635682838730ee804","canRetry":false,"verifyId":"628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site","renderData":{"code":"1000","callbackType":"H5_CB_Function"},"success":true,"verifySuccess":true,"resultCode":"SUCCESS","isFinish":true,"resultMessage":"SUCCESS","extendInfo":{"leftTimes":"3"}}
```

6. Now some sort of pubKey getting request happens:

request:
```http
GET /merchant/proxyapi/member/getPubKey.json?_route=QK&ctoken=lryb1T619p2sp8uG HTTP/2
Host: global.alipay.com
Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; tntInstId=ALIPW3SG; intl_locale=en_US; session.cookieNameId=ALIPAYINTLJSESSIONID; LOGON_FLAG=true; CROSS_TOKEN_REGION=5; registered="0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja"; cna=WuwNIrbXvmgCASXS+B42LsSs; _region=QK; ALIPAYJSESSIONID=GZ00wRpBaCy75qdaPSgmZ98jgrZnoBglobalprodGZ00; ALIPAYINTLJSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; ctoken=lryb1T619p2sp8uG; sofaId=218425b917704628178841494ea712; x-hng=lang=en-US; _CHIPS-x-hng=lang=en-US; JSESSIONID=A406B1DA587D87A25B6446D536C0C8EE; spanner=62RRqIUjiHhtpa1mShifqluCJkufgNrX; tfstk=gQQIkG4TkvDIfHPLevPZh2U4aq8WR5z4ybORi_3EweLKF76OUWYPwkV7P_XST3eH8a61QtOP8arhVQpOwpRyUkV5CTWl8pRFaQB1wtgyvT8EFz66CLkUEehhjt5x8wrHz4THrUe43rz4t6Yky4YgRHDnXBA7z0pp2eY9TXundrzVt6d_5B2UuMkk5vOJeUKp2ch9IIdpyQdL1ddWi0HdeUF_1QOmeDKpvcd9tI8JeTL811pMwUddeUF16dA-BTZ66k9NO7GDQ0GtdkCkC43R5CFhd6NtPC7BOH9A9wg-y7ABAKCpIJ9gZT-OZ3_oZ4tP9iXkM9HLFLb16wIAHRoepiO5gg6YaDAwVwY6ewUmGdQCNNthbvnpGe9BDwKIgSfX2G_68weom156pnTNbl2e4e6CmKxLjRX51pWRRhHQQLSV_wK1HRu1E3sR8FQLBrsz6qJXyBoS1n0W1KP_10mk8gWaeD5xYtKpsCc415iqqx0-ynV_10kJvCAg95Nsm01..; isg=BLe3UShwkgl0ahaEB8_I-whARqsBfIvedz1c1AlkQgbtuNP6XE6yLA3engDmUGNW
Sec-Ch-Ua-Platform: "Windows"
Ctoken: lryb1T619p2sp8uG
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Bx-V: 2.5.36
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://global.alipay.com/merchant/portal/account/set-login-pwd/0xkujen-ywh-fdd598ecef7c9f7b%40yeswehack.ninja?_route=QK
Accept-Encoding: gzip, deflate, br
Priority: u=1, i


```

response:
```http
HTTP/2 200 OK
Server: nginx/1.6.2
Date: Sat, 07 Feb 2026 11:28:43 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 495
Strict-Transport-Security: max-age=31536000
Itraceid: 21841fac17704637229276079e74a7
Content-Language: en-US
Set-Cookie: JSESSIONID=2BFA88C2A57900519F4D43F2FD437CC4; Path=/; HttpOnly
Set-Cookie: JSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; Path=; Secure; HttpOnly
Set-Cookie: spanner=BSv9pkJPcZx4CNCRcDh5XxVGb2E5RV/t;path=/;secure;
Via: ispanner-prod-30.sg113y[200]
Origin-Agent-Cluster: ?0

{"success":true,"data":{"publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgOc9+/N66dgZaBMbLj7kPSg0rsw78mXbSS6HZ1slb/BCbMiDKCSsa6IugHAgfqf12o+J1uYAYndXTiFJECXVTy9zM8++zMuB6u+zWxACApdl0SfeiljJn5+bn+aW283paIgySz/Ra7I2nzTifoFwlFIDwWj2H44x3Db7vadW7PKpDJrZ4jcDn/N2bqip5DLZm5VSmwfMgG+gaeEV9OhZmhL72SOWyDQHj4/QgM6aaWgIznIlXh/aduq3HrCO26YoQfJR8PsQzsVQcQlw2cmWFMJguRF/csU24gLYqiP3LYQ2nhg976ZiRQM6PKhexRuKaWE0q9ZAWk2w3RnYdeQrkwIDAQAB","salt":"UWzJtShhmF7N","uid":"7GDOg8MueQOpKs427zAp6EClh9iUs9BP"}}
```

7. Now a reset logon password request happens that takes our input password in encrypted state:

request:
```http
POST /merchant/merchantservice/api/account/resetLogonPassword.json?_route=QK&ctoken=lryb1T619p2sp8uG HTTP/2
Host: global.alipay.com
Cookie: tntInstId=ALIPW3SG; intl_locale=en_US; session.cookieNameId=ALIPAYINTLJSESSIONID; LOGON_FLAG=true; CROSS_TOKEN_REGION=5; registered="0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja"; cna=WuwNIrbXvmgCASXS+B42LsSs; _region=QK; ALIPAYJSESSIONID=GZ00wRpBaCy75qdaPSgmZ98jgrZnoBglobalprodGZ00; ALIPAYINTLJSESSIONID=GZ00TLNe6ap9jEEaIgaHJa2DEQvqcHiloginGZ00; ctoken=lryb1T619p2sp8uG; sofaId=218425b917704628178841494ea712; x-hng=lang=en-US; _CHIPS-x-hng=lang=en-US; JSESSIONID=2BFA88C2A57900519F4D43F2FD437CC4; spanner=BSv9pkJPcZx4CNCRcDh5XxVGb2E5RV/t; tfstk=gFpmk00EYI5X7FUrKPWjNMZSK0l-ct66QFeOWOQZaa7WkOBx1OmGrFX9DOhjQQYwPsQ2Dm1NSETG6RBVBFfwAFXOujgfSFxpyRQVkmswEUTWknK90hzwRaTG1m_O7NY9bIn-pvKXcO6NI2HKpg3CaCY0_R5qb7SNX0I4gWQ8kO6ZJ4EwqTLNCEYomUBw40jOX5zw7NWrqMjdQ-5a37zPPGWNQ1y448SOj5yaQGok4asNQN8NQ0XPPGWN7FWZBWgVudJvU2b8qyz2gbvdmsbe0Z8OPLkPgStPryzeEQfc8vQuQRJlchutpHen6wRCk6QBzYecI3SMr6dm--YMbHONZd4qDe-wlLXfKfnftQRJ9sAouRbJHGfFQ_qaQ3XlPevNLvzlVQ-v_KT0jRSXHpCGR_maC1Byp6ReoliB4tSw569tR-_2bH9B99D0RiAyxTjPo7PE-9214cpz151VVgbKPR3eo3GgLDmoqWb1ggsVJdnuwACVVg7mq0VHjsS5mS5..; isg=BNXVDCZeEJPi3TTuOXEKsd725NGP0onkQes-vld6JMybrvGgUiAwtpsofKoYrqGc
Content-Length: 551
Sec-Ch-Ua-Platform: "Windows"
Ctoken: lryb1T619p2sp8uG
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not(A:Brand";v="8", "Chromium";v="144"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: application/json
Content-Type: application/json;charset=UTF-8
Bx-V: 2.5.36
Origin: https://global.alipay.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://global.alipay.com/merchant/portal/account/set-login-pwd/0xkujen-ywh-fdd598ecef7c9f7b%40yeswehack.ninja?_route=QK
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"encryptedQueryPassword":"TNlGz0M7zv+HreCqIyZG5WmzJ7u+oSxjLTIVv4IBs7lc71KJXM15MtfAIWogOB7ULRgv6QMiIKIJm4Ves0K6uL0AuQo0XUj1SmmEjU3S/KG67q8z6+sJbBT689coNE419oC+f0suZPC+ZB+63YSdpfQSBkmJu6s95YjNYqqaHIGxnHosbk6+9zOaboCxwnuM2rEWUGgry2/XFfyrMf/s/EoR+xP56xXZstwOdIOG4BT4kKhHEwRYMqU6yDRVDwCrWrcVDZfiPnZrkCJCir3RP3F7waYRTaXe3w4YL+H7V3QEF5Ub4Wo04sNA44PHKzEKXKT7gIt713z/5g/NbBOJmg==","uid":"7GDOg8MueQOpKs427zAp6EClh9iUs9BP","verifyId":"628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site","securityId":"628c7e947ea536ee4f2550bc6f08ef9a","verifyProductCode":"otpEmail"}
```

response:
```http
HTTP/2 200 OK
Server: nginx/1.6.2
Date: Sat, 07 Feb 2026 11:28:44 GMT
Content-Type: application/json;charset=UTF-8
Vary: Accept-Encoding
Strict-Transport-Security: max-age=31536000
Access-Control-Allow-Origin: https://global.alipay.com
Access-Control-Allow-Credentials: true
Set-Cookie: registered="0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja"; Domain=.alipay.com; Path=/; Secure; HttpOnly
Itraceid: 21841fac17704637232586080e74a7
Set-Cookie: intl_loginInfo=" "; Domain=.alipay.com; Expires=Thu, 01-Jan-1970 00:00:10 GMT; Path=/; Secure; HttpOnly
Content-Language: en-US
Set-Cookie: spanner=/kOUm2H6tfWDFwEYme36x9NVbR2asDEj;path=/;secure;
Via: ispanner-prod-2.sg113y[200]
Origin-Agent-Cluster: ?0

{"passwordVo":{"uid":"7GDOg8MueQOpKs427zAp6EClh9iUs9BP","encryptedPayPassword":"","verifyId":"628c7e947ea536ee4f2550bc6f08ef9a_out_qk_site","syncAlipayCNScene":"","securityId":"628c7e947ea536ee4f2550bc6f08ef9a","encryptedQueryPassword":"TNlGz0M7zv+HreCqIyZG5WmzJ7u+oSxjLTIVv4IBs7lc71KJXM15MtfAIWogOB7ULRgv6QMiIKIJm4Ves0K6uL0AuQo0XUj1SmmEjU3S/KG67q8z6+sJbBT689coNE419oC+f0suZPC+ZB+63YSdpfQSBkmJu6s95YjNYqqaHIGxnHosbk6+9zOaboCxwnuM2rEWUGgry2/XFfyrMf/s/EoR+xP56xXZstwOdIOG4BT4kKhHEwRYMqU6yDRVDwCrWrcVDZfiPnZrkCJCir3RP3F7waYRTaXe3w4YL+H7V3QEF5Ub4Wo04sNA44PHKzEKXKT7gIt713z/5g/NbBOJmg==","scene":""},"success":true,"traceId":"21841fac17704637232586080e74a7"}
```

and done