# ViewState
ViewState sayfanın ve tüm kontrollerinin durumudur. ASP.NET framework tarafından otomatik olarak post işlemleri arasında korunur.
Bir sayfa istemciye gönderildiğinde, sayfa ve kontrollerin özelliklerindeki değişiklikler belirlenir ve bunlar _VIEWSTATE adlı gizli bir input alanının değerinde saklanır. Sayfa tekrar sunucuya post edildiğinde, _VIEWSTATE alanı HTTP isteğiyle birlikte sunucuya gönderilir.

Event validation, POST isteğiyle gelen değerlerin bilinen ve geçerli değerler olduğunu kontrol eder. Eğer çalışma zamanı tanımadığı bir değer görürse bir exception fırlatır. Bu parametre de seri hale getirilmiş veriler içerir.

Formatters, veriyi bir formattan başka bir formata dönüştürmek için kullanılır. Örneğin, BinaryFormatter, bir nesneyi veya bağlı nesnelerden oluşan bir grafiği binary formatta serileştirir ve deserialize eder.

Gadgets, güvensiz veriler tarafından işlendiğinde kod çalıştırılmasına imkân verebilecek sınıflardır. .NET için bazı örnekler: PSObject, TextFormattingRunProperties, TypeConfuseDelegate.

Gadgets, güvensiz veriler tarafından işlendiğinde kod çalıştırılmasına imkân verebilecek sınıflardır. .NET için bazı örnekler: PSObject, TextFormattingRunProperties, TypeConfuseDelegate.

ViewState temelde sunucu tarafından üretilir ve “POST” isteklerinde kullanılmak üzere istemciye _VIEWSTATE isimli gizli bir form alanı olarak gönderilir. Daha sonra istemci, POST işlemi sırasında bunu tekrar sunucuya gönderir. ViewState, serileştirilmiş bir veri biçimindedir ve postback sırasında sunucuya gönderildiğinde deserialize edilir. ASP.NET, veriyi byte-stream (bayt akışı) ve tersi arasında serileştirmek/deserileştirmek için farklı formatter kütüphaneleri kullanır: ObjectStateFormatter, LOSFormatter, BinaryFormatter vb. ASP.NET, ViewState’i serileştirmek için LosFormatter kullanır ve bunu istemciye gizli form alanı olarak yollar. İstemciden POST isteğiyle geri geldiğinde ise deserialize işlemi ObjectStateFormatter ile yapılır.