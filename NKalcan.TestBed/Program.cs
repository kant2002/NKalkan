using NKalcan;

var certificatePath = "GOSTKNCA_60e31061cedbcc9f917a2be0fb8ec3c04eb4b598.p12";
var certificatePassword = "Qwerty12";
var documentToSign = "<xml><MyData /></xml>";
var client = new KalkanApi();

client.LoadKeyStore(KalkanStorageType.PKCS12, certificatePath, certificatePassword);
var signXml = client.SignXml(documentToSign);

Console.WriteLine(signXml);