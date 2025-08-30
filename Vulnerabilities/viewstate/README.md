# ViewState
ViewState sayfanın ve tüm kontrollerinin durumudur. ASP.NET framework tarafından otomatik olarak post işlemleri arasında korunur.
Bir sayfa istemciye gönderildiğinde, sayfa ve kontrollerin özelliklerindeki değişiklikler belirlenir ve bunlar _VIEWSTATE adlı gizli bir input alanının değerinde saklanır. Sayfa tekrar sunucuya post edildiğinde, _VIEWSTATE alanı HTTP isteğiyle birlikte sunucuya gönderilir.
