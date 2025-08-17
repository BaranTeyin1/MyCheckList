# XXE Nedir
XXE, uygulamanın kullanıcıdan aldığı XML verisini güvenli olmayan bir parser ile işlemesi sonucunda ortaya çıkan bir zafiyettir. Saldırgan ```<!DOCTYPE>``` ve ```<!ENTITY>``` tanımları aracılığıyla dış kaynaklara erişebilir, sunucu üzerindeki dosyaları okuyabilir, iç ağa istek gönderebilir ya da parser’ı kötüye kullanarak DoS saldırıları gerçekleştirebilir.

#  External Entity Nedir
XML işleminde, External Entity bir XML elementidir ve harici bir kaynağa (örneğin bir dosya veya URL) referans verebilir. Eğer güvenli şekilde işlenmezse, XXE açığı oluşur. Bu da saldırganların bu entity’leri kullanarak harici dosyalara erişmesine veya kötü amaçlı sunucu taraflı işlemler gerçekleştirmesine olanak tanır.