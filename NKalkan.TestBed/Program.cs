using NKalkan;
using System.Text;

var api = new KalkanApi();
LoadCertificateFromStore(api);
SignXml(api);
SignData(api);
SignWsse(api);

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
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "<xml><MyData /></xml>";

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedXml = api.SignXml(documentToSign);

    Console.WriteLine(signedXml);
    try
    {
        api.VerifyXml(signedXml);
        Console.WriteLine("XML verified successfully!");
    }
    catch (Exception e)
    {
        Console.WriteLine(e.Message);
    }
}

void SignWsse(KalkanApi api)
{
    Console.WriteLine("Testing WSSE signing");
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var messageId = "123";
    var messageBody = """
<ContactQueryPage_Input xmlns="urn:crmondemand/ws/ecbs/contact/10/2004">
        <ListOfContact xmlns="urn:/crmondemand/xml/Contact/Query">
        <Contact>
            <Id>1-asdfd</Id>
        </Contact>
        </ListOfContact>
    </ContactQueryPage_Input>
""";

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedXml = api.SignWsse(messageBody, messageId);

    Console.WriteLine(signedXml);
    try
    {
        api.VerifyXml(signedXml);
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
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "Super important data";
    var data = Encoding.UTF8.GetBytes(documentToSign); // this is to simulate some byte content

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signedData = api.SignData(data, KalkanSignFlags.SignCms | KalkanSignFlags.InputPem | KalkanSignFlags.OutputPem);

    Console.WriteLine(signedData);

    // api.VerifyData(data, signedData, KalkanSignFlags.SignCms | KalkanSignFlags.InputPem | KalkanSignFlags.OutputPem | KalkanSignFlags.DoNotCheckCertificateTime);
    // Console.WriteLine("Data verified successfully!");
}