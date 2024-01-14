# NKalcan

Библиотека для работы с криптопровайдером АО "НУЦ" [KalkanCrypt](https://pki.gov.kz/developers/)

Данная библиотека использует C API, в том числе на Windows. KalkanCryptCOM.dll не используется.

## Особенности работы с Windows.

В настройках Windows надо установить системную локаль на Kazakh (Kazakhstan).
Это позволит прочитать названия организаций корректно.

Так как НУЦ не разрешает распространять бинарники, то надо самостоятельно положить `SDK 2.0\C\Windows\KalkanCrypt_С\lib\x64\KalkanCrypt.dll` в папку с конечным исполняемым файлом.
Как например `NKalcan.TestBed\bin\Debug\net7.0`.

Тестовые ключи находятся в папке `SDK 2.0\Keys and Certs\Gost2004 and RSA\2023.02.01_valid\Физическое лицо\ДЕЙСТВУЮЩИЕ`.
Дополнительные тестовые файлы используемые в проэкте TestBed можно найти в папке `SDK 2.0\C\Linux\C\test\example`

# Особенности настройки Linux

Эта библиотека требует чтобы стандартные механизмы загрузки SO файлов на Linux заработали для `libkalkancryptwr-64.so`
Или настройте в соответсвии с инструкциями в файле `C/Linux/C/README.txt` или можете выполнить следующие операции
- скопируйте файлы `setup.sh` и `ld.kalkan.conf` в папку `C/Linux/C/` вашего SDK
- перейдите в папку `C/Linux/C/`
- запустите `setup.sh`


## Поддержка MacOS

У меня нету Мака, потому есть вероятность что какие то проблемы есть. Если обнаружите баг, то создайте тикет в Гитхабе.

# Примеры использования

* [Подпись XML документа](#подпись-xml-документа)
* [Проверка XML документа](#проверка-xml-документа)
* [Формирование CMS](#формирование-cms)
* [Проверка CMS](#проверка-cms)
* [Загрузка ключа из памяти](#загрузка-ключа-из-памяти)

## Работа с казахскими символами

Для работы с XML содержащим кириллицу или казахские символы надо делать XML-эскейпинг. Пример функции и использования:

```csharp
[return: NotNullIfNotNull(nameof(s))]
static string? XmlEscape(string? s)
{
    if (string.IsNullOrEmpty(s))
        return s;

    return string.Join("", s.Select(c => c < 127 ? c.ToString() : "&#" + (short)c + ";"));
}

    var messageBody = $"""
<?xml version="1.0" encoding="UTF-8"?>
<sendMessageRequest>
    <request>
        <requestInfo>
            <messageId>0f3d8368-215a-4a20-a306-5222548f5e87</messageId>
            <serviceId>ServiceID</serviceId>
            <sessionId>4958523f-423a-45bb-1aa1-5222548f5e87</sessionId>
            <messageDate>2018-12-11T11:45:12.574+06:00</messageDate>
            <sender>
                <senderId>login</senderId>
                <password>password</password>
            </sender>
        </requestInfo>
        <requestData>
            <data>
                    <uin>810918350135</uin>
                    <company>{XmlEscape("ЗАО Складские решения")}</company>
                    <company_bin>12345678</company_bin>
                    <expiresIn>600000</expiresIn>
                    <omit-sms>false</omit-sms>
            </data>
        </requestData>
    </request>
</sendMessageRequest>
""";
```

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

## Формирование CMS

```csharp
using NKalkan;

var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
var certificatePassword = "Qwerty12";
var documentToSign = "<xml><MyData /></xml>";
var data = Encoding.UTF8.GetBytes(documentToSign);
var client = new KalkanApi();

client.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
var signedData = client.SignData(documentToSign, KalkanSignType.Cms, KalkanInputFormat.Pem, KalkanOutputFormat.Pem);

Console.WriteLine(signedData);
```

## Проверка CMS

```csharp
try
{
    api.VerifyData(data, signedData, KalkanSignType.Cms, KalkanInputFormat.Pem, KalkanOutputFormat.Pem);
    Console.WriteLine("Data verified successfully!");
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
}
```

## Загрузка ключа из памяти

Загрузка из массива байт

```csharp
var certificateBytes = File.ReadAllBytes(certificatePath);
api.LoadKeyStore(KalkanStorageType.PKCS12, certificateBytes, certificatePassword);
```

Загрузка из потока

```csharp
using var stream = File.OpenRead(certificatePath);
api.LoadKeyStore(KalkanStorageType.PKCS12, stream, certificatePassword);
```

Загрузка из массива байт

```csharp
var base64Content = Convert.ToBase64String(File.ReadAllBytes(certificatePath));
api.LoadKeyStoreFromBase64(KalkanStorageType.PKCS12, base64Content, certificatePassword);
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
| X509ValidateCertificate     | :white_check_mark: |
| HashData     | :white_check_mark: |
| SignHash     | :white_check_mark: |
| SignData     | :white_check_mark: |
| SignXML     | :white_check_mark: |
| VerifyData     | :white_check_mark: |
| VerifyXML     | :white_check_mark: |
| KC_getCertFromXML     | :white_check_mark: |
| KC_getSigAlgFromXML     | :white_check_mark: |
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
