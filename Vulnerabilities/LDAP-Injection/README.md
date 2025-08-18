# LDAP Injection
LDAP Injection, kullanıcıdan alınan parametrenin filtrelenmeden doğrudan LDAP sorgusuna eklenmesiyle ortaya çıkan bir güvenlik zafiyetidir. Saldırgan, sorguya kötü amaçlı ifadeler enjekte ederek hassas verilere erişebilir, komut çalıştırabilir veya uygulama içerisindeki yetkilerini yükseltebilir. Bu saldırı, mantık olarak SQL Injection zafiyetine oldukça benzer.

# LDAP Nedir
LDAP (Lightweight Directory Access Protocol), dizin servislerine erişmek ve yönetmek için kullanılan bir protokoldür. Kullanıcı kimlik doğrulaması için bir depo görevi görür ve SSO (Single Sign-On) mekanizmasına olanak tanır. Yaygın olarak yetki yönetimi, kaynak yönetimi ve erişim kontrolü süreçlerinde kullanılır.

# LDAP Injection Nasıl Çalışır
LDAP sorguları genellikle kullanıcı girişlerinde, kimlik doğrulama mekanizmalarında veya arama fonksiyonlarında kullanılır. Örneğin, bir uygulama kullanıcıdan aldığı kullanıcı adı ve şifre parametrelerini doğrudan LDAP filtresine ekliyorsa, saldırgan bu parametreleri manipüle ederek sorgunun mantığını değiştirebilir.

Örnek olarak şu basit LDAP filtresini ele alalım:
```ldap
(&(uid=admin)(userPassword=12345))
```

Ancak saldırgan kullanici_adi alanına şu değeri gönderirse:
```ldap
*)(|(uid=*))
```

Sorgu şu hale dönüşür:
```ldap
(&(uid=*)(|(uid=*))(userPassword=12345))
```

Bu durumda filtre, tüm kullanıcıları döndürebilir ve kimlik doğrulama mekanizması bypass edilebilir.