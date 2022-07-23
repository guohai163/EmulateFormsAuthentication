## EmulateFormsAuthentication Prject

FormsAuthentication 是微软在.Net2时推的一套WEB程序的验证机制，会把用户的标识信息加密后存储在浏览器的cookies中。但微软在.net core支持跨平台后在 System.Web.Security NS下就已经不两万提供此类了。
但从2.0或4.0过来的项目肯定还是要考虑兼容性问题。还好微软开源了[.net4.8的源码](https://referencesource.microsoft.com/#System.Web/Security/FormsAuthentication.cs,a820aab5aa1ac27c)在里面可以看到实现的方式.

### 模拟类库实现原理

Cookies 当中存储的是 FormsAuthenticationTicket 这个成员对象串行化后的数据,当中会包含版本、过期时间、标识等信息。串行的方法是会把票据序列化版本号写第一位，当前为0x01 然后是ticket的内容。最后存储一个0xff 用来标记数据区的结束。
串行化数据后就是做一个Hash操作，支持的Hash有[sha1/md5/sha256/sha384/sha512]，会把HASH的结果追加到数据串后后面。

接下来我们就开始准备对我们的数据进行加密了，这里支持的对称加密算法[AES/DES/3DES]。加密完成后还会对数据串再进行一个HASH并填充到数据串的末尾。最后整个数据串的格式如下

~~~ c#
Crypto(Serialize(ticket) + hash(Serialize(ticket))) + hash()
~~~

解密就是反向操作并进行HASH验证即可。

这次我们直接用最新的.Net 6来进行实现。


### 使用

当前已发布的NuGet版本为 0.1.0 直接安装即可。

~~~ shell
dotnet add package EmulateFormsAuthentication --version 0.1.0
~~~

当前版本 对于加密仅支持 3DES，对于 hash 仅支持 Sha1。

~~~ c#
FormsAuthentication formsAuthentication = new FormsAuthentication(decryptionKey, validationKey);

FormsAuthenticationTicket formsAuthenticationTicket = new FormsAuthenticationTicket(1, "username", new DateTime(), new DateTime(2055, 1, 1), false, "User Data", "/");
// 加密
string encryptData = formsAuthentication.Encrypt(formsAuthenticationTicket);
// 解密
FormsAuthenticationTicket formsAuthenticationTicket1 = formsAuthentication.Decrypt(encryptData);

~~~