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