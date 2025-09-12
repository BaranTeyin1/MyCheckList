# Authentication Brute Force
Brute force saldırısı, saldırganın geçerli kullanıcı kimlik bilgilerini tahmin etmek için deneme-yanılma sistemini kullandığı bir saldırıdır. Bu saldırılar genellikle kullanıcı adları ve parolalardan oluşan kelime listeleri kullanılarak otomatikleştirilir. Bir brute force saldırısının, saldırganın bir hesabı başarılı şekilde ele geçirmeden önce birçok başarısız tahmin içermesi büyük olasılıktır. Mantıken brute-force koruması, süreci otomatikleştirmeyi mümkün olduğunca zorlaştırmak ve saldırganın deneme hızını yavaşlatmak etrafında şekillenir. Brute-force saldırılarını önlemenin en yaygın iki yolu şunlardır:
- Kullanıcının çok fazla başarısız giriş denemesi yapması durumunda erişmeye çalıştığı hesabı kilitlemek
- Kullanıcının IP adresini kısa süre içinde çok fazla giriş denemesi yaparsa engellemek

Ek olarak, HTTP basic authentication uygulamaları çoğunlukla brute-force korumasını desteklemez. Token yalnızca statik değerlerden oluştuğundan, brute-force’a karşı savunmasız kalabilir.

HTTP basic authentication ayrıca kendi başına koruma sağlamadığı için özellikle CSRF gibi oturumla ilgili açıklar açısından hassastır.

# Brute Force Saldırısını Önlemek
- Progressive delay: Aynı IP veya hesap için başarısız deneme sayısı arttıkça cevap süresini uzat.
- CAPTCHA: Şüpheli denemelerde veya belirli eşik aşıldığında ek doğrulama olarak göster.
- Multi-Factor Authentication (MFA): OTP/Push/UC bir faktör ekle.
- Rate limiting: IP veya kullanıcı başına saniye/dakika bazlı limitler uygula.
- IP reputasyon & coğrafi kısıtlama: Şüpheli IP'ler için daha katı kurallar uygula; şüpheli coğrafyalardan gelen istekleri ekstra zorlaştır.
- Account lockout politikaları: Tam kalıcı kilitleme DoS oluşturabilir. Tavsiye: kısa süreli kilitleme + kullanıcıya e-posta bildirimi + admin/auto-unlock.
- Adaptive / risk-based auth: Olağandışı cihaz, location veya hız farkı görürsen MFA zorunlu kıl.
- Güçlü parola politikası & zayıf parola reddi: Yaygın parolaları engelle, zayıf parola kullanımını reddet.
- Monitoring & alerting: Anormal başarısız giriş dalgaları için uyarı ve loglama (SIEM entegrasyonu).