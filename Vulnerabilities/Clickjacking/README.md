# Clickjacking Nedir?
Clickjacking, kullanıcıyı farkında olmadan gizli veya zararlı bir işlem yapmaya zorlayan bir saldırdır. Saldırgan hedef web sayfasını görünmez bir iframe içerisine kendi kontrol ettiği bir sayfaya yerleştirir ve kullanıcı buton veya bağlantıya tıkladığını zannederken aslında arka planda zararlı içeriğe tıklamış olur. İframe, kullanıcının dikkatini çeken içeriğin üstünde görünmez şekilde yer alır.

CSRF saldırılarına karşı önlem amaçlı genellikle CSRF token kullanılır. Ancak Clickjacking saldırıları CSRF ile engellenemez çünkü hedef oturum gerçek bir web sitesinden yüklenen içerikle başlatılır ve istekler aynı domain üzerinden gerçekleşir.

# İframe Nedir?
iFrame bir HTML içerisinde başka Web sayfasındaki herhangi bir kaynağı kullanmak ve render ederek göstermek istediğiniz zaman kullanabileceğimiz iç çerçevelerdir.

# Temel Bir Saldırı Nasıl Oluşturulur.
Clickjacking saldırıları, css kullanılarak katmanlar oluşturma ve katmanları manipüle etme prensibiyle çalışır. Saldırgan hedef web sitesini bir iframe olarak sahte web sitesinin üzerine bindirir. Aşağıda bir örnek verilmiştir.

```html
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
		...burada sahte web içeriği yer alır...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

Bu örnekte, hedef web sitesine ait iframe, tarayıcı içinde hedef eylem ile sahte sitedeki öğe ile çakışacak şekilde hizalanır. Ekran boyutu, tarayıcı türü ve platformdan bağımsız olarak tutarlı hizalama sağlamak için obsolute ve relative pozisyon değerleri kullanılır.
z-index ise iframe ve diğer katmanların hangi sırayla üst üste bindirileceğini belirler.
opacity (saydamlık) değeri 0.0 (veya 0.00001 gibi çok düşük bir değer) yapılarak iframe tamamen görünmez hale getirilir.

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

Hem allow-forms hem de allow-scripts değerleri iframe içinde belirtilen işlemlere izin verirken, en üst seviye navigasyon engellenir.

# Multistep Clickjacking
Saldırganın hedef web sitesine yönelik giriş verilerini (input) manipüle etmesi, birden fazla eylem gerçekleştirmesini gerektirebilir. Bu tür işlemler, saldırgan tarafından birden fazla div veya iframe kullanılarak gerçekleştirilebilir. 

# Clickjacking saldırılarını Önlemek
Clickjacking saldırıları hedef site sadece iframe içerisinde gösterilebildiği sürece mümkündür. Bu yüzden, önleyici teknikler genellikle web sitelerinin iframe içinde gösterilmesini engellemeye dayanır. Yaygın bir istemci tarafı koruma yöntemi, tarayıcıda çalışan frame busting script’lerinin kullanılmasıdır. Bunlar, NoScript gibi tarayıcıya özel JavaScript eklentileri ya da uzantılarla uygulanabilir. Bu script’ler genellikle aşağıdaki davranışlardan bazılarını veya tamamını gerçekleştirir:

- Mevcut uygulama penceresinin ana ya da en üst pencere olduğunu kontrol etmek ve bunu zorunlu kılmak,

- Tüm iframe’leri görünür yapmak,

- Görünmez iframe’ler üzerindeki tıklamaları engellemek,

- Potansiyel clickjacking saldırılarını yakalayıp kullanıcıya bildirmek

Frame busting'i bypasslamak için kullanılan bir yöntem HTML5'in iframe sandbox özelliğini kullanmaktır. Bu istemci tarafı bir önlemdir. Sunucu tarafında clickjacking’e karşı iki temel koruma mekanizması vardır: X-Frame-Options ve Content Security Policy (CSP).

## X-Frame-Options
Bu header, web site sahibine iframe veya object etiketleriyle sayfanın başka bir sayfa içinde gösterilip gösterilemeyeceği konusunda kontrol sağlar.

Aşağıdaki direktif ile sayfanın iframe içinde gösterilmesi tamamen yasaklanabilir:

```http
X-Frame-Options: deny
```

Alternatif olarak, sayfanın sadece aynı origin içerisinde gösterilmesine izin verilebilir:

```http
X-Frame-Options: sameorigin
```
Veya sadece belirli bir domain’e izin verilerek şu şekilde sınırlandırılabilir:

```http
X-Frame-Options: allow-from https://normal-website.com
```
## CSP
Content Security Policy (CSP), XSS ve clickjacking gibi saldırılara karşı algılama ve önleme sağlayan bir güvenlik mekanizmasıdır. Clickjacking'e karşı önerilen koruma yöntemi, uygulamanın CSP’sine frame-ancestors direktifini dahil etmektir:
- frame-ancestors 'none'; → X-Frame-Options: deny ile aynı işlevi görür.
- frame-ancestors 'self'; → X-Frame-Options: sameorigin ile yaklaşık olarak eşdeğerdir.

Örneğin, sadece aynı domain içinde çerçevelemeye izin veren CSP şu şekildedir:

```http
Content-Security-Policy: frame-ancestors 'self';
```

Alternatif olarak, yalnızca belirli sitelerin sayfayı iframe içinde göstermesine izin verilebilir:

```http
Content-Security-Policy: frame-ancestors normal-website.com;
```

Referanslar:
https://portswigger.net/web-security/clickjacking
https://www.intigriti.com/researchers/hackademy/clickjacking