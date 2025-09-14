# Çok Faktörlü Kimlik Doğrulama Zafiyetleri
Bir saldırganın bazen parola gibi tek bir bilgi tabanlı faktörü elde etmesi mümkün olsa da, aynı anda dış-bant bir kaynaktan gelen başka bir faktörü elde etmesi çok daha az olasıdır. Bu nedenle, iki faktörlü kimlik doğrulama tek faktörlüye göre açıkça daha güvenlidir. Ancak, her güvenlik önleminde olduğu gibi, uygulanma biçimi kadar güvenlidir. Kötü uygulanmış iki faktörlü kimlik doğrulama, tek faktörlü kimlik doğrulama gibi aşılabilir veya tamamen atlatılabilir.

Eğer kullanıcı önce parola girme işlemine yönlendiriliyor, sonra ayrı bir sayfada doğrulama kodunu girmesi isteniyorsa, kullanıcı doğrulama kodunu girmeden önce teknik olarak “oturum açmış” bir durumda demektir. Bu durumda, ilk kimlik doğrulama adımını tamamladıktan sonra doğrudan “sadece oturum açmış kullanıcıların görebildiği” sayfalara atlayıp atlamadığınızı test etmek faydalıdır. Bazen bir site ikinci adımın tamamlanıp tamamlanmadığını kontrol etmeden sayfayı yükleyebilir.

## Hatalı İki Faktör Doğrulama Mantığı
Bazen iki faktörlü doğrulamadaki mantık hatası şu anlama gelir: kullanıcı ilk adımı tamamladıktan sonra sitenin ikinci adımı yapan kullanıcının aynı kişi olduğunu yeterince doğrulamaması.

Örneğin kullanıcı normal kimlik bilgileriyle ilk adımda oturum açar:
```
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty
```

Ardından hesapla ilişkili bir çerez atanır ve kullanıcı giriş sürecinin ikinci adımına yönlendirilir:
```
HTTP/1.1 200 OK
Set-Cookie: account=carlos

GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```

Doğrulama kodunu gönderirken ise hangi hesabın erişilmeye çalışıldığını belirlemek için bu çerez kullanılır:
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=carlos
...
verification-code=123456
```

Bu durumda bir saldırgan kendi kimlik bilgileriyle oturum açıp, ardından doğrulama kodunu gönderirken account çerezinin değerini herhangi bir kullanıcı adıyla değiştirebilir:
```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```

## 2FA Doğrulama Kodlarının Kaba Kuvvetle Kırılması
Parolalarda olduğu gibi, web siteleri 2FA doğrulama kodlarının kaba kuvvetle denenmesini önlemek için önlemler almalıdır. Bu özellikle önemlidir çünkü kod genellikle basit bir 4 veya 6 haneli sayıdır. Yeterli kaba kuvvet koruması olmadan bu tür bir kodu kırmak kolaydır.

# Doğru Şekilde Çok Faktörlü Kimlik Doğrulama Uygulama
SMS tabanlı 2FA teknik olarak iki faktörü doğrulasa da, SIM swapping gibi kötüye kullanım ihtimalleri nedeniyle bu sistem güvenilir olmayabilir.
İdeal olarak 2FA, doğrulama kodunu doğrudan üreten özel bir cihaz veya uygulama ile uygulanmalıdır. Güvenlik sağlamak için özel olarak tasarlandıklarından, genellikle daha güvenlidirler.
Son olarak, ana kimlik doğrulama mantığında olduğu gibi, 2FA kontrollerinizin mantığının da sağlam olduğundan emin olun ki kolayca atlatılamasın.