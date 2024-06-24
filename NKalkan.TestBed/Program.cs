using NKalkan;
using System.Diagnostics.CodeAnalysis;
using System.Text;

var api = new KalkanApi();
LoadCertificateFromStore(api);
SignXml(api);
SignData(api);
SignWsse(api);
HashData(api);
HashDataFromFile(api);
LoadKeyStoreFromMemory(api);
ValidateCertificate(api);

void LoadCertificateFromStore(KalkanApi api)
{
    Console.WriteLine("Reading certificate information");
    api.LoadCertificateFromFile("test_CERT_GOST.txt", KalkanCertificateType.UserCertificate);
    var certificate = api.ExportCertificateFromStore();
    Console.WriteLine(certificate);

    Console.WriteLine($@"Issuer: {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerCountryName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerSOPN)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerLocalityName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerOrganizationName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerOrganizationUnitName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.IssuerCommonName)}");
    Console.WriteLine($@"Subject: {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectCountryName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectSOPN)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectLocalityName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectCommonName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectGivenName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectSurname)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectSerialNumber)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectEmail)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectOrganizationName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectOrganizationUnitName)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectBC)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectDC)}
Validity:
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.NotBefore)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.NotAfter)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.KeyUsage)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.ExtendedKetUsage)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.AuthorityKeyId)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SubjectKeyId)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.CertificateSN)}
    {api.GetCertificateProperty(certificate, KalkanCertificateProperty.SignatureAlgorithm)}");
}

void SignXml(KalkanApi api)
{
    Console.WriteLine("Testing XML signing");
    // Keys and Certs\Gost2004 and RSA\2023.11.17_valid\Физическое лицо\valid\
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";
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
    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedXml = api.SignXml(messageBody);

    Console.WriteLine(signedXml);
    try
    {
        var normalized = XmlEscape(signedXml);
        api.VerifyXml(normalized);
        Console.WriteLine("XML verified successfully!");
    }
    catch (Exception e)
    {
        Console.WriteLine(e.Message);
    }
}

[return: NotNullIfNotNull(nameof(s))]
static string? XmlEscape(string? s)
{
    if (string.IsNullOrEmpty(s))
        return s;

    return s;// string.Join("", s.Select(c => c < 127 ? c.ToString() : "&#" + (short)c + ";"));
}

void SignWsse(KalkanApi api)
{
    Console.WriteLine("Testing WSSE signing");
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";
    var messageId = "123";
    var messageBody = $"""
<ContactQueryPage_Input xmlns="urn:crmondemand/ws/ecbs/contact/10/2004">
        <ListOfContact xmlns="urn:/crmondemand/xml/Contact/Query">
        <Contact>
            <Id>{XmlEscape("1-фывфыв")}</Id>
        </Contact>
        </ListOfContact>
</ContactQueryPage_Input>
""";

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedXml = api.SignWsse(messageBody, messageId);

    Console.WriteLine(signedXml);
    try
    {
        var normalized = XmlEscape(signedXml);
        api.VerifyXml(normalized);
        Console.WriteLine("XML verified successfully!");
    }
    catch (Exception e)
    {
        Console.WriteLine(e.Message);
    }
}

void SignData(KalkanApi api)
{
    Console.WriteLine("Testing plain data signing");
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "Super important data";
    var data = Encoding.UTF8.GetBytes(documentToSign); // this is to simulate some byte content

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedData = api.SignData(data, KalkanSignType.Cms, KalkanInputFormat.Pem, KalkanOutputFormat.Pem);

    Console.WriteLine(signedData);

try
{
    api.VerifyData(data, signedData, KalkanSignFlags.SignCms | KalkanSignFlags.InputPem | KalkanSignFlags.OutputPem | KalkanSignFlags.DoNotCheckCertificateTime);
    Console.WriteLine("Data verified successfully!");
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
}
}

void HashData(KalkanApi api)
{
    Console.WriteLine("Testing data hashing");
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";
    var documentToHash = "Super important data122222ds ahdhasdhasd asdas das d asd asd adsa das dasd asd asd";
    var data = Encoding.UTF8.GetBytes(documentToHash); // this is to simulate some byte content

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var hashedData = api.HashData(KalkanHashAlgorithm.Gost95, data, KalkanSignType.Cms, KalkanInputFormat.Pem, KalkanOutputFormat.Base64);

    Console.WriteLine(hashedData);
    
    var signedHash = api.SignHash(KalkanHashAlgorithm.Gost95, Encoding.UTF8.GetBytes(hashedData), KalkanSignType.Cms, KalkanInputFormat.Base64, KalkanOutputFormat.Pem);

    Console.WriteLine(signedHash);
}

void HashDataFromFile(KalkanApi api)
{
    Console.WriteLine("Testing hashing file content");
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";
    var documentToHash = "Super important data122222ds ahdhasdhasd asdas das d asd asd adsa das dasd asd asd";
    var data = Encoding.UTF8.GetBytes(documentToHash); // this is to simulate some byte content

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var hashedData = api.HashData(KalkanHashAlgorithm.Gost95, certificatePath, KalkanSignType.Cms, KalkanInputFormat.File, KalkanOutputFormat.Base64);

    Console.WriteLine(hashedData);
}

void LoadKeyStoreFromMemory(KalkanApi api)
{
    Console.WriteLine("Loading key from memory");
    var certificatePath = "AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12";
    var certificatePassword = "Qwerty12";

    api.LoadKeyStore(KalkanStorageType.PKCS12, File.ReadAllBytes(certificatePath), certificatePassword);
    Console.WriteLine("Key store from binary data loaded.");

    api.LoadKeyStoreFromBase64(KalkanStorageType.PKCS12, Convert.ToBase64String(File.ReadAllBytes(certificatePath)), certificatePassword);
    Console.WriteLine("Key store from base64 data loaded.");

    using var stream = File.OpenRead(certificatePath);
    api.LoadKeyStore(KalkanStorageType.PKCS12, stream, certificatePassword);
    Console.WriteLine("Key store from from stream loaded.");
}

void ValidateCertificate(KalkanApi api)
{
    api.LoadCertificateFromFile("test_CERT_GOST.txt", KalkanCertificateType.UserCertificate);
    var certificate = api.ExportCertificateFromStore();
    api.ValidateCertificateOscp(certificate, false, out var outputInformation, out var ospResponse);
    Console.WriteLine($"Output information:\n{outputInformation}\nOSP Response:\n{ospResponse}");
}