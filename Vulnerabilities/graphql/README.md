# GraphQL
GraphQL bir sorgu dilidir. Yani, SQL gibi, bir veritabanına ya da herhangi bir bilgi sistemine erişmek için kullanılan bir dildir. Schema, bir GraphQL API'nin merkez öğesidir. Sunucu ile istemci arasındaki tüm olası etkileşimleri tanımlar. Bir API için yalnızca bir schema vardır ve bu şema bir referans görevi görür. Schema, istemcinin sunucuya gönderebileceği sorgu türlerini, sunucudan alınabilecek veri türlerini ve bu farklı veri türleri arasındaki ilişkileri belirtir. Aşağıdaki örnekte, Product tipinin basit bir şema tanımı gösterilmiştir. ! operatörü, alanın boş geçilemez (non-nullable) olduğunu yani zorunlu olduğunu belirtir.

```graphql
type Product {
    id: ID!
    name: String!
    description: String!
    price: Int
}
```

GraphQL sorguları, veri deposundan veri almak için kullanılır. REST API’lerdeki GET isteklerine yaklaşık olarak denktir. Bir sorgu genellikle şu temel bileşenlere sahiptir:
- Sorgu operasyon tipi: Teknik olarak opsiyoneldir ancak tavsiye edilir. Sunucuya gelen isteğin bir sorgu olduğunu açıkça belirtir.
- Sorgu adı: İsteğe bağlıdır ama tavsiye edilir, çünkü hata ayıklamayı kolaylaştırır.
- Veri yapısı: Sorgunun döndürmesini istediğimiz veriyi belirtir.
- Opsiyonel argümanlar: Belirli bir nesneyi hedeflememizi sağlar (örneğin, “ID’si 123 olan ürünün adını ve açıklamasını getir”).

Örnek sorgu:
```
query myGetProductQuery {
    getProduct(id: 123) {
        name
        description
    }
}
```

Ürün tipinde daha fazla alan bulunuyor olabilir, ancak burada yalnızca adı ve açıklaması istenmiştir. Sadece ihtiyaç duyulan alanların alınabilmesi, GraphQL’in en esnek özelliklerinden biridir.

# GraphQL API Zafiyetleri
GraphQL saldırıları genellikle kötü niyetli istekler şeklinde olur ve saldırganın veri elde etmesine veya yetkisiz işlemler yapmasına olanak sağlayabilir. Eğer kullanıcı admin yetkilerini sorguları manipüle ederek veya CSRF istismarı ile elde edebilirse etkisi ciddi olur. Zafiyetli GraphQL API’ler ayrıca information disclosure sorunlarına yol açabilir.

Bir GraphQL API’yi test etmeden önce, önce endpoint’ini bulman gerekir. GraphQL API’ler tüm istekler için aynı endpoint’i kullandığından, bu bilgi değerlidir. Herhangi bir GraphQL endpoint’ine query{__typename} gönderirsen, yanıtın içinde {"data": {"__typename": "query"}} dizesi yer alır. Buna universal query denir ve bir URL’nin GraphQL servisi olup olmadığını anlamak için kullanışlıdır.

## Introspection
Introspection, GraphQL’in bir özelliğidir. Sunucunun şemasını sorgulamamıza ve mevcut tipler, query’ler, mutation’lar hakkında bilgi almamıza izin verir. Ancak bu, ciddi bir information disclosure riskidir. Çünkü saldırgan, API ile nasıl etkileşim kuracağını öğrenebilir. Introspection, API ile nasıl etkileşim kurabileceğini anlamana yardımcı olur ve potansiyel olarak hassas bilgileri açığa çıkarabilir.

Basit bir sorgu ile introspection test edilebilir:
```
{
    "query": "{__schema{queryType{name}}}"
}
```

Endpoint üzerinde mümkün olduğunca fazla şema bilgisi almak için tam introspection sorgusu çalıştırabilirsin. Bu, tüm query, mutation, subscription, type ve fragment bilgilerini döndürür.
```
query IntrospectionQuery {
    __schema { ... }
}
fragment FullType on __Type { ... }
fragment InputValue on __InputValue { ... }
fragment TypeRef on __Type { ... }
```

Geliştirici sadece __schema{ ifadesini filtrelediyse, aşağıdaki introspection sorgusu engellenmeyecektir:
```
{
    "query": "query{__schema
    {queryType{name}}}"
}
```

## Suggestions
Introspection tamamen kapalı olsa bile, bazı bilgiler suggestions üzerinden elde edilebilir. Apollo GraphQL platformunda, sunucu hata mesajlarında sorgu düzeltme önerileri sunar. Örneğin: "There is no entry for 'productInfo'. Did you mean 'productInformation'?" Bu yanıtlar, geçerli şema parçalarını öğrenmene yardımcı olabilir. Clairvoyance aracı, önerileri kullanarak introspection kapalı olsa bile şemanın tamamını veya bir kısmını otomatik çıkarabilir.

## Rate Limiting’i Aliases ile Bypass Etmek
Aliases, API çağrı sayısını azaltmak için tasarlanmıştır ama aynı zamanda brute force işlemleri için de kullanılabilir.
```
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```

## GraphQL CSRF
GraphQL de CSRF saldırıları için bir vektör olabilir. Saldırgan, kurbanın tarayıcısının kurban kullanıcı olarak kötü amaçlı sorgu göndermesini sağlayacak bir exploit oluşturabilir.

# GraphQL Saldırılarını Önleme
- API’niz genel kullanım için değilse, introspection’ı devre dışı bırakın. Bu, saldırganların API’nin nasıl çalıştığı hakkında bilgi edinmesini zorlaştırır ve istenmeyen bilgi sızıntısı riskini azaltır.
- Suggestions (kapalı olmalıdır. Bu, saldırganların Clairvoyance veya benzeri araçları kullanarak şema bilgisi edinmesini önler.
- API şemanızın kullanıcıya özel alanları, örneğin e-posta adresleri veya kullanıcı ID’leri, açığa çıkarmadığından emin olun.
- Query derinliğini sınırlayın. Query derinliği, bir sorgu içindeki iç içe geçmiş seviyelerin sayısıdır. Çok derin sorgular performans sorunlarına yol açabilir ve kabul edilirse DoS saldırılarına fırsat verebilir. Query derinliğini sınırlayarak bu riski azaltabilirsiniz.
- Operation limitlerini yapılandırın. Bu, API’nizin kabul edebileceği maksimum benzersiz alan, alias ve root field sayısını sınırlar.
- API yalnızca JSON-encoded POST üzerinden sorguları kabul etmelidir.
- API, gönderilen içeriğin belirtilen content-type ile eşleştiğini doğrulamalıdır.