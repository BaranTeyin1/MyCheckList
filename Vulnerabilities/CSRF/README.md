# CSRF
CSRF bir saldırganın kullanıcıları istemedikleri işlemleri yapmaya zorlamasına izin veren bir web güvenlik zafiyetidir. Başarılı bir CSRF saldırısında, saldırgan mağdur kullanıcının istemeden bir işlem gerçekleştirmesini sağlar. Bu, hesabın e-posta adresinin değiştirilmesi, şifrenin değiştirilmesi olabilir. Yapılan işleme bağlı olarak, saldırgan kullanıcının hesabı üzerinde tam kontrole erişebilir. Eğer ele geçirilen kullanıcı uygulama içinde yetkili bir role sahipse, saldırgan uygulamanın tüm veri ve işlevleri üzerinde tam kontrol elde edebilir. 

Bir CSRF saldırısının mümkün olması için üç ana koşul bulunmalıdır:
- Çerez tabanlı oturum yönetimi. İşlemi gerçekleştirmek bir veya daha fazla HTTP isteği göndermeyi gerektirir ve uygulama yalnızca oturum çerezlerine dayanarak isteği yapan kullanıcıyı tanımlar. İstekleri doğrulamak veya oturumları takip etmek için başka bir mekanizma yoktur.
- Tahmin edilebilir olmayan istek parametrelerinin olmaması. İşlemi gerçekleştiren isteklerde saldırganın belirleyemeyeceği veya tahmin edemeyeceği değerler içermemelidir. Örneğin, bir kullanıcının şifresini değiştirirken saldırganın mevcut şifrenin değerini bilmesi gerekiyorsa işlem CSRF'ye karşı korunmuş sayılır.

Örnek olarak, uygulamada kullanıcının hesap e-postasını değiştirmesine izin veren bir fonksiyon olduğunu varsayalım. Kullanıcı bu işlemi gerçekleştirdiğinde aşağıdaki gibi bir HTTP isteği yapılır:
```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

Bu durum CSRF için gerekli koşulları karşılıyor:
- Bir kullanıcının e-posta adresini değiştirme işlemi saldırganın ilgisini çeker. Bu işlemden sonra saldırgan genellikle şifre sıfırlama tetikleyip kullanıcının hesabını tamamen ele geçirebilir.
- Uygulama, isteği yapan kullanıcıyı tanımlamak için oturum çerezini kullanır. İstekleri doğrulamak için başka bir token veya mekanizma yoktur.
- Saldırgan, işlemi gerçekleştirmek için gereken istek parametrelerinin değerlerini kolayca belirleyebilir.

Bu koşullar varsa, saldırgan aşağıdaki HTML içeren bir web sayfası oluşturabilir:
```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

Bir mağdur kullanıcı saldırganın sayfasını ziyaret ederse şu olur:
- Saldırganın sayfası, savunmasız web sitesine bir HTTP isteği tetikler.
- Kullanıcı savunmasız web sitesine giriş yapmışsa tarayıcı isteğe otomatik olarak oturum çerezini ekler.
- Savunmasız site isteği normal şekilde işler, isteği mağdur kullanıcının yaptığı kabul eder ve e-posta adresini değiştirir.

# CSRF Saldırısını Önlemek
- Hassas bir işlem yapıldığında istemci isteğe doğru CSRF tokenını eklemelidir. Bu, saldırganın mağdur adına geçerli bir istek oluşturmasını çok zorlaştırır.
- SameSite kısıtlamaları saldırganın bu işlemleri tetiklemesini engelleyebilir.
