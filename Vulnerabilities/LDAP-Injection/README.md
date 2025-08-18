# LDAP Injection
LDAP Injection, kullanıcıdan alınan parametrenin filtrelenmeden doğrudan LDAP sorgusuna eklenmesiyle ortaya çıkan bir güvenlik zafiyetidir. Saldırgan, sorguya kötü amaçlı ifadeler enjekte ederek hassas verilere erişebilir, komut çalıştırabilir veya uygulama içerisindeki yetkilerini yükseltebilir. Bu saldırı, mantık olarak SQL Injection zafiyetine oldukça benzer.

# LDAP Nedir
LDAP (Lightweight Directory Access Protocol), dizin servislerine erişmek ve yönetmek için kullanılan bir protokoldür. Kullanıcı kimlik doğrulaması için bir depo görevi görür ve SSO (Single Sign-On) mekanizmasına olanak tanır. Yaygın olarak yetki yönetimi, kaynak yönetimi ve erişim kontrolü süreçlerinde kullanılır.