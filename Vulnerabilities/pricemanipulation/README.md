# Price Manipulation
Fiyat manipülasyonu zafiyetleri, e-ticaret platformlarında ve Web 3.0’ın yükselişiyle birlikte merkeziyetsiz finans (DeFi) platformlarında da görülen güvenlik açıklarıdır.

## Formula Injection
Doğrulanmamış kullanıcı girdisinin doğrudan fiyatı belirleyen matematiksel hesaplamalara veya fonksiyonlara eklenmesiyle ortaya çıkan bir güvenlik açığıdır. Enjekte edilebilecek yer ve parametreye bağlı olarak saldırgan, hesaplamayı değiştirerek fiyatı düşürebilir veya en kötü senaryoda sıfıra ayarlayarak ürünü ücretsiz sipariş edebilir.

### Formül Enjeksiyonu ile Fiyat Manipülasyonu
Formül enjeksiyonu, kullanıcı girdisinin doğrudan fiyat hesaplamasında kullanılmasına dayanır. Örneğin:
- Bir “amount” parametresi checkout isteğinde değiştirilip 0.01 yapılırsa, ürün neredeyse bedavaya satın alınabilir.

### Formül Enjeksiyonu ile Quantity Manipülasyonu
Sipariş fiyatını belirleyen bir diğer parametre ürün adedidir.

#### Negatif adet
Doğrulama yapılmazsa, adedi negatif sayıya çekerek formülü manipüle edebiliriz.

Örneğin:
- Ürün 1: 2 adet = 400 USD
- Ürün 2: -1 adet = -100 USD

Toplam: 500 yerine 300 USD ödenir.

#### Ondalık adet
Benzer şekilde adet değerine ondalık sayı verilirse, toplam fiyat yine manipüle edilebilir.

#### Integer Overflow
Sayıların bellekteki sınırları aşıldığında integer overflow oluşur.
Çok büyük bir sayı gönderildiğinde backend bunu negatif veya sıfır olarak algılayabilir.
Bu da fiyatın ya da adedin 0 olmasıyla ödeme bypass’ına yol açabilir.

### Kuponlar
- Tekrar kullanım: Kuponun sadece bir kez kullanılabilmesi gerekir. Doğrulama yapılmazsa tekrar tekrar kullanılabilir.
- Süre kontrolü eksikliği: Süresi geçmiş kuponlar hâlâ kullanılabiliyorsa fiyat indirilebilir.
- Kişisel kuponlar: Doğum günü kuponu gibi tek seferlik indirimler, profil bilgilerinin değiştirilmesiyle tekrar tekrar alınabilir.

### Para Birimi Karışıklığı (Currency Confusion)
Birden fazla para birimini destekleyen sitelerde, fiyat doğrulaması eksikse manipülasyon yapılabilir.

Örneğin:
- Ürün fiyatı: 100 USD
- stek parametresinde para birimi INR yapılırsa, ödeme 100 INR (~1.10 USD) olur.

