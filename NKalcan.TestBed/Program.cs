using NKalcan;

var api = new KalkanApi();
LoadCertificateFromStore(api);
SignXml(api);

void LoadCertificateFromStore(KalkanApi api)
{
    api.LoadCertificateFromFile("test_CERT_GOST.txt", KalkanCertificateType.UserCertificate);
    var certificate = api.ExportCertificateFromStore();
    Console.WriteLine(certificate);
}

void SignXml(KalkanApi api)
{
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "<xml><MyData /></xml>";

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signXml = api.SignXml(documentToSign);

    Console.WriteLine(signXml);
}