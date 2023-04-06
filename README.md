# NKalcan

Библиотека для работы с криптопровайдером АО "НУЦ" [KalkanCrypt](https://pki.gov.kz/developers/)

Данная библиотека использует C API, в том числе на Windows. KalkanCryptCOM.dll не используется.

## Особенности работы с Windows.

В настройках Windows надо установить системную локаль на Kazakh (Kazakhstan).
Это позволит прочитать названия организаций корректно.

Так как НУЦ не разрешает распространять бинарники, то надо самостоятельно положить KalkanCrypt_x64.dll в папку с конечным исполняемым файлом.
Как например `NKalcan.TestBed\bin\Debug\net7.0`.

# Особенности настройки Linux

Эта библиотека требует чтобы стандартные механизмы загрузки SO файлов на Linux заработали для `libkalkancryptwr-64.so`
Или настройте в соответсвии с инструкциями в файле `C/Linux/C/README.txt` или можете выполнить следующие операции
- скопируйте файлы `setup.sh` и `ld.kalkan.conf` в папку `C/Linux/C/` вашего SDK
- перейдите в папку `C/Linux/C/`
- запустите `setup.sh`


## Поддержка MacOS

У меня нету Мака, потому есть вероятность что какие то проблемы есть. Если обнаружите баг, то создайте тикет в Гитхабе.

# Примеры использования

## Подпись XML документа

```csharp
using NKalkan;

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

# Реализованные API методы

Если вам нужны определенные методы прямо сейчас, создайте задачу в Гитхабе, и с большой вероятностью вы увидите
это в следующем релизе.

| Метод | Статус | 
| ----- | --- |
| KC_GetTokens     | :white_large_square: |
| KC_GetCertificatesList     | :white_large_square: |
| KC_LoadKeyStore     | :white_check_mark: |
| X509LoadCertificateFromFile     | :white_large_square: |
| X509LoadCertificateFromBuffer     | :white_large_square: |
| X509ExportCertificateFromStore     | :white_large_square: |
| X509CertificateGetInfo     | :white_large_square: |
| X509ValidateCertificate     | :white_large_square: |
| HashData     | :white_check_mark: |
| SignHash     | :white_check_mark: |
| SignData     | :white_check_mark: |
| SignXML     | :white_check_mark: |
| VerifyData     | :white_check_mark: |
| VerifyXML     | :white_check_mark: |
| KC_getCertFromXML     | :white_large_square: |
| KC_getSigAlgFromXML     | :white_large_square: |
| KC_GetLastError     | :white_check_mark: |
| KC_GetLastErrorString     | :white_check_mark: |
| KC_XMLFinalize     | :white_large_square: |
| KC_Finalize     | :white_large_square: |
| KC_TSASetUrl     | :white_large_square: |
| KC_GetTimeFromSig     | :white_large_square: |
| KC_SetProxy     | :white_large_square: |
| KC_GetCertFromCMS     | :white_large_square: |
| SignWSSE     | :white_check_mark: |
| ZipConVerify     | :white_large_square: |
| ZipConSign     | :white_large_square: |

# Лицензия

Данное ПО опубликовано под MIT лицензией.
