# NKalcan

## Особенности работы с Windows.

В настройках Windows надо установить системную локаль на Kazakh (Kazakhstan).
Это позволит прочитать названия организаций корректно.

Так как НУЦ не разрешает распространять бинарники, то надо самостоятельно положить KalkanCrypt_x64.dll в папку с конечным исполняемым файлом.
Как например `NKalcan.TestBed\bin\Debug\net7.0`.

## Подпись XML документа

```csharp
using NKalcan;

var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
var certificatePassword = "Qwerty12";
var documentToSign = "<xml><MyData /></xml>";
var client = new KalkanApi();

client.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
var signedXml = client.SignXml(documentToSign);

Console.WriteLine(signedXml);
```

## Проверка XML документа

```csharp
try
{
    api.VerifyXml(signedXml);
    Console.WriteLine("XML verified successfully!");
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
}
```