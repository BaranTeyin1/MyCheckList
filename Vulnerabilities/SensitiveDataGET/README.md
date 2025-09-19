# Sensitive Data GET
Bazı uygulamalar, hassas verileri göndermek için GET metodunu kullanmaktadır. Bu durumda veriler, talep edilen URL’nin query string kısmında iletilir. URL içindeki hassas bilgiler; kullanıcının tarayıcısında, web sunucusunda ve istemci ile sunucu arasındaki tüm forward veya reverse proxy sunucularında loglanabilir. Ayrıca URL’ler ekranda görüntülenebilir, kullanıcılar tarafından yer imlerine eklenebilir veya e-posta ile paylaşılabilir. Kullanıcı bir dış site bağlantısına tıkladığında, bu veriler Referer header aracılığıyla üçüncü taraflara da sızabilir.

Hassas verilerin URL üzerinden gönderilmesi, saldırganlar tarafından ele geçirilme riskini artırır. Bununla birlikte, bu tür bir zafiyet, log kayıtları veya ağ izleri gibi kanıtların gizlenmesi nedeniyle olayın araştırılmasını da zorlaştırır.

# Öneri
Tüm hassas veri gönderen formlar POST metodunu kullanmalıdır.
Bunu sağlamak için uygulamalar, FORM etiketinde method özniteliğini method="POST" olarak belirtmelidir. Ayrıca, hassas verilerin URL yerine mesaj gövdesinden (message body) alınabilmesi için sunucu tarafındaki form işleyicisinin de buna uygun şekilde güncellenmesi gerekebilir.