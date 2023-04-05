using NKalcan;
using System.Text;

var api = new KalkanApi();
LoadCertificateFromStore(api);
SignXml(api);
SignData(api);

void LoadCertificateFromStore(KalkanApi api)
{
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
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "<xml><MyData /></xml>";

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signXml = api.SignXml(documentToSign);

    Console.WriteLine(signXml);
}

void SignData(KalkanApi api)
{
    var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
    var certificatePassword = "Qwerty12";
    var documentToSign = "Super important data";
    var data = Encoding.UTF8.GetBytes(documentToSign); // this is to simulate some byte content

    api.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
    var signXml = api.SignData(data, KalkanSignFlags.SignCms | KalkanSignFlags.InputPem | KalkanSignFlags.OutputPem);

    Console.WriteLine(signXml);
}