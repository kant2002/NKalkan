using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NKalkan;

public sealed class KalkanApi
{
    private const int CertificateLength = 32768;
    [DllImport("KalkanCrypt_x64", CallingConvention = CallingConvention.Cdecl)]
    static extern int KC_GetFunctionList(out FunctionsType kc);

    private static StKCFunctionsType StKCFunctionsType;
    private static bool initialized;
    private bool keyStoreLoaded;

    static unsafe KalkanApi()
    {
#if NETCOREAPP3_0_OR_GREATER
        NativeLibrary.SetDllImportResolver(typeof(KalkanApi).Assembly, (string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
        {
            if (NativeLibrary.TryLoad("libkalkancryptwr-64.so", out var kalkanLib))
            {
                return kalkanLib;
            }

            if (NativeLibrary.TryLoad("KalkanCrypt.dll", assembly, searchPath, out var kalkanLibDll))
            {
                return kalkanLibDll;
            }

            return IntPtr.Zero;
        });
#endif

        int result = KC_GetFunctionList(out var functionsType);
        if (result != 0)
        {
            throw new InvalidOperationException($"Couldn't get function list result: {result}");
        }

        if (functionsType.stKCFunctionsType != IntPtr.Zero)
        {
            StKCFunctionsType = Marshal.PtrToStructure<StKCFunctionsType>(functionsType.stKCFunctionsType);
        }

        var errCode = StKCFunctionsType.KC_Init();
        ThrowIfError(errCode);
        initialized = true;
    }

    public void LoadKeyStore(KalkanStorageType storeType, string containerPath, string password, string? certificateAlias = null)
    {
        EnsureInitialized();
        var errCode = StKCFunctionsType.KC_LoadKeyStore((int)storeType, password, password.Length, containerPath, containerPath.Length, certificateAlias);
        ThrowIfError(errCode);

        keyStoreLoaded = true;
    }

    public void LoadKeyStore(KalkanStorageType storeType, byte[] containerContent, string password, string? certificateAlias = null)
    {
        EnsureInitialized();
        var tempFile = Path.GetTempFileName();
        File.WriteAllBytes(tempFile, containerContent);
        var errCode = StKCFunctionsType.KC_LoadKeyStore((int)storeType, password, password.Length, tempFile, tempFile.Length, certificateAlias);
        ThrowIfError(errCode);

        keyStoreLoaded = true;
    }

    public void LoadKeyStore(KalkanStorageType storeType, Stream containerContent, string password, string? certificateAlias = null)
    {
        EnsureInitialized();
        var tempFile = Path.GetTempFileName();
        using (var file = File.OpenWrite(tempFile))
        {
            containerContent.CopyTo(file);
        }

        var errCode = StKCFunctionsType.KC_LoadKeyStore((int)storeType, password, password.Length, tempFile, tempFile.Length, certificateAlias);
        ThrowIfError(errCode);

        keyStoreLoaded = true;
    }

    public void LoadKeyStoreFromBase64(KalkanStorageType storeType, string containerContentBase64, string password, string? certificateAlias = null)
    {
        byte[] containerContent = Convert.FromBase64String(containerContentBase64);
        LoadKeyStore(storeType, containerContent, password, certificateAlias);
    }

    public unsafe void LoadCertificateFromFile(string certificatePath, KalkanCertificateType certificateType)
    {
        EnsureInitialized();

        var certificatePathPtr = Marshal.StringToHGlobalAnsi(certificatePath);
        try
        {
            var errorCode = StKCFunctionsType.X509LoadCertificateFromFile(certificatePathPtr, (int)certificateType);
            ThrowIfError(errorCode);
            keyStoreLoaded = true;
        }
        finally
        {
            Marshal.FreeHGlobal(certificatePathPtr);
        }
    }

    public string ExportCertificateFromStore(string? certificateAlias = null)
    {
        EnsureInitialized();
        int certificateLength = CertificateLength;
        StringBuilder certificate = new StringBuilder(CertificateLength);
        var errorCode = StKCFunctionsType.X509ExportCertificateFromStore(certificateAlias, 0, certificate, ref certificateLength);
        ThrowIfError(errorCode);
        return certificate.ToString();
    }

    public string GetCertificateProperty(string certificate, KalkanCertificateProperty property)
    {
        EnsureInitialized();
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        int certificateLength = certificate.Length;
        int certificatePropertyLength = 2048;
        StringBuilder certificateProperty = new StringBuilder(certificatePropertyLength);
        var errorCode = StKCFunctionsType.X509CertificateGetInfo(certificate, certificateLength, (int)property, certificateProperty, ref certificatePropertyLength);
        if (errorCode == KalkanError.GETCERTPROPERR)
        {
            return string.Empty;
        }

        ThrowIfError(errorCode);
        return certificateProperty.ToString();
    }

    public void ValidateCertificateOscp(string certificate, out string outputInformation, out string ospResponse)
    {
        ValidateCertificateOscp(certificate, true, out outputInformation, out ospResponse);
    }

    public void ValidateCertificateOscp(string certificate, bool checkCertificateTime, out string outputInformation, out string ospResponse)
    {
        ValidateCertificate(certificate, KalkanValidationType.Ocsp, "http://ocsp.pki.gov.kz/", checkCertificateTime, true, out outputInformation, out ospResponse);
    }

    public void ValidateCertificateOscp(string certificate, bool checkCertificateTime, out string outputInformation, out string ospResponse, string validPath = "http://ocsp.pki.gov.kz/")
    {
        ValidateCertificate(certificate, KalkanValidationType.Ocsp, validPath, checkCertificateTime, true, out outputInformation, out ospResponse);
    }

    public void ValidateCertificateOscp(string certificate, out string outputInformation)
    {
        ValidateCertificateOscp(certificate, true, out outputInformation);
    }

    public void ValidateCertificateOscp(string certificate, bool checkCertificateTime, out string outputInformation)
    {
        ValidateCertificate(certificate, KalkanValidationType.Ocsp, "http://ocsp.pki.gov.kz/", checkCertificateTime, false, out outputInformation, out var _);
    }

    public void ValidateCertificate(string certificate, KalkanValidationType validationType, string validPath, bool checkCertificateTime, bool getOscpResponse, out string outputInformation, out string ospResponse)
    {
        EnsureInitialized();
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        int certificateLength = Encoding.UTF8.GetByteCount(certificate);
        int outputInformationLength = 64 * 1024;
        int ospResponseLength = getOscpResponse ? 128 * 1024 : 0;

        int flag = (checkCertificateTime ? 0 : KalkanConstants.KC_NOCHECKCERTTIME) + (getOscpResponse ? KalkanConstants.KC_GET_OCSP_RESPONSE : 0);

        byte[] outputInformationBuf = new byte[outputInformationLength];
        byte[]? ospResponseBuf = getOscpResponse ? new byte[ospResponseLength] : null;

        var errorCode = StKCFunctionsType.X509ValidateCertificate(certificate, certificateLength, (int)validationType, validPath, checkTime: 0, outputInformation: outputInformationBuf, ref outputInformationLength, flag, ocsPResponse: ospResponseBuf, ref ospResponseLength);
        ThrowIfError(errorCode);

        outputInformation = Encoding.UTF8.GetString(outputInformationBuf, 0, outputInformationLength);

        if (getOscpResponse && ospResponseBuf != null && ospResponseLength > 0)
            ospResponse = Convert.ToBase64String(ospResponseBuf, 0, ospResponseLength);
        else
            ospResponse = string.Empty;
    }

    public string SignXml(string content, KalkanSignFlags flags = 0, string? certificateAlias = null, string? signNodeId = null, string? parentSignNode = null, string parentNameSpace = "")
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (parentNameSpace is null)
        {
            throw new ArgumentNullException(nameof(parentNameSpace));
        }

        var signedPayloadLength = 0;
        var contentLength = Encoding.UTF8.GetByteCount(content);
        var errorCode = StKCFunctionsType.SignXML(certificateAlias, (int)flags, content, contentLength, null, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.SignXML(certificateAlias, (int)flags, content, contentLength, signedPayload, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string VerifyXml(string content, KalkanSignFlags flags = 0, string? certificateAlias = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();

        var signedPayloadLength = 0;
        var contentLength = Encoding.UTF8.GetByteCount(content);
        var errorCode = StKCFunctionsType.VerifyXML(certificateAlias, (int)flags, content, contentLength, null, ref signedPayloadLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.VerifyXML(certificateAlias, (int)flags, content, contentLength, signedPayload, ref signedPayloadLength);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string SignData(byte[] content, KalkanSignType signType, KalkanInputFormat inputFormat, KalkanOutputFormat outputFormat, string? certificateAlias = null, string? inputSignature = null)
    {
        var flags = SignFlags(signType, inputFormat, outputFormat);

        return SignData(content, flags, certificateAlias, inputSignature);
    }

    public string SignData(byte[] content, KalkanSignFlags flags, string? certificateAlias = null, string? inputSignature = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.SignData(certificateAlias, (int)flags, content, content.Length, inputSignature, inputSignature?.Length ?? 0, null, ref signedPayloadLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.SignData(certificateAlias, (int)flags, content, content.Length, inputSignature, inputSignature?.Length ?? 0, signedPayload, ref signedPayloadLength);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string VerifyData(byte[] content, string inputSignature, KalkanSignType signType, KalkanInputFormat inputFormat, KalkanOutputFormat outputFormat, string? certificateAlias = null)
    {
        var flags = SignFlags(signType, inputFormat, outputFormat);

        return VerifyData(content, inputSignature, flags, certificateAlias);
    }

    public string VerifyData(byte[] content, string inputSignature, KalkanSignFlags flags, string? certificateAlias = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        var dataLength = 28000;
        var verifyInfoLength = 64768;
        var certificateLength = 64768;
        var data = new StringBuilder(dataLength);
        var verifyInfo = new StringBuilder(verifyInfoLength);
        var certificate = new StringBuilder(certificateLength);
        var errorCode = StKCFunctionsType.VerifyData(certificateAlias, (int)flags, content, content.Length, inputSignature, inputSignature?.Length ?? 0,
            data, ref dataLength, verifyInfo, ref verifyInfoLength, 0, certificate, ref certificateLength);
        ThrowIfError(errorCode);
        return verifyInfo.ToString();
    }

    public string SignWsse(string content, string? signNodeId, KalkanSignFlags flags = 0, string? certificateAlias = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (signNodeId is null)
        {
            throw new ArgumentNullException(nameof(signNodeId));
        }

        var documentToSign = $"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Body wsu:id="{signNodeId}">{content}</s:Body>
</s:Envelope>
""";
        var documentToSignBytes = Encoding.UTF8.GetBytes(documentToSign);
        var signedPayloadLength = 0;
        var documentToSignLength = documentToSign.Length;
        var errorCode = StKCFunctionsType.SignWSSE(certificateAlias, (int)flags, documentToSignBytes, documentToSignLength, Array.Empty<byte>(), ref signedPayloadLength, signNodeId);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new byte[signedPayloadLength];
        errorCode = StKCFunctionsType.SignWSSE(certificateAlias, (int)flags, documentToSignBytes, documentToSignLength, signedPayload, ref signedPayloadLength, signNodeId);
        ThrowIfError(errorCode);
        return Encoding.UTF8.GetString(signedPayload, 0, signedPayloadLength).TrimEnd('\0');
    }

    /// <summary>
    /// Sing envelope with custom xml attributes 
    /// </summary>
    /// <param name="envelope"></param>
    /// <param name="signNodeId"></param>
    /// <param name="flags"></param>
    /// <param name="certificateAlias"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public string SignWsseRaw(string envelope, string? signNodeId, KalkanSignFlags flags = 0, string? certificateAlias = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (signNodeId is null)
        {
            throw new ArgumentNullException(nameof(signNodeId));
        }

        // Convert input XML to UTF-8 bytes
        byte[] inData = Encoding.UTF8.GetBytes(envelope);
        int inDataLength = inData.Length;

        // First call to get required output length (pass null for outSign)
        int outSignLength = 0;
        var errorCode = StKCFunctionsType.SignWSSE(certificateAlias, (int)flags, inData, inDataLength, Array.Empty<byte>(), ref outSignLength, signNodeId);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        // Allocate output buffer and sign
        byte[] outSign = new byte[outSignLength];
        errorCode = StKCFunctionsType.SignWSSE(certificateAlias, (int)flags, inData, inDataLength, outSign, ref outSignLength, signNodeId);
        ThrowIfError(errorCode);

        // Convert output bytes back to string (trim any null terminator if present)
        return Encoding.UTF8.GetString(outSign, 0, outSignLength).TrimEnd('\0');
    }

    public string HashData(string algorithm, byte[] content, KalkanSignType signType, KalkanInputFormat inputFormat, KalkanOutputFormat outputFormat)
    {
        var flags = SignFlags(signType, inputFormat, outputFormat);
        return HashData(algorithm, content, flags);
    }

    public string HashData(string algorithm, byte[] content, KalkanSignFlags flags = 0)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (algorithm is null)
        {
            throw new ArgumentNullException(nameof(algorithm));
        }

        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.HashData(algorithm, (int)flags, content, content.Length, null, ref signedPayloadLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        // This is magic number which seems to be required.
        // even if actual produced base64 string would be of size signedPayloadLength
        // without padding with this 20 bytes I always receive BUFFER_TOO_SMALL.
        signedPayloadLength = signedPayloadLength + 20;
        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.HashData(algorithm, (int)flags, content, content.Length, signedPayload, ref signedPayloadLength);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string HashData(string algorithm, string fileName, KalkanSignType signType, KalkanInputFormat inputFormat, KalkanOutputFormat outputFormat)
    {
        var fileNameBytes = Encoding.UTF8.GetBytes(fileName);
        return HashData(algorithm, fileNameBytes, signType, inputFormat, outputFormat);
    }

    public string HashData(string algorithm, string fileName, KalkanSignFlags flags = 0)
    {
        var fileNameBytes = Encoding.UTF8.GetBytes(fileName);
        return HashData(algorithm, fileNameBytes, flags);
    }

    public string SignHash(string algorithm, byte[] content, KalkanSignType signType, KalkanInputFormat inputFormat, KalkanOutputFormat outputFormat)
    {
        var flags = SignFlags(signType, inputFormat, outputFormat);

        return SignHash(algorithm, content, flags);
    }

    public string SignHash(string algorithm, byte[] content, KalkanSignFlags flags = 0)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (algorithm is null)
        {
            throw new ArgumentNullException(nameof(algorithm));
        }

        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.SignHash(algorithm, (int)flags, content, content.Length, null, ref signedPayloadLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.SignHash(algorithm, (int)flags, content, content.Length, signedPayload, ref signedPayloadLength);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string GetCertificateFromXml(string? xmlString)
    {
        return GetCertificateFromXml(xmlString, 1);
    }

    public string GetCertificateFromXml(string? xmlString, int signId)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (xmlString is null)
        {
            throw new ArgumentNullException(nameof(xmlString));
        }

        var certificateLength = 0;
        var errorCode = StKCFunctionsType.KC_getCertFromXML(xmlString, xmlString.Length, signId, null, ref certificateLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var certificate = new StringBuilder(certificateLength);
        errorCode = StKCFunctionsType.KC_getCertFromXML(xmlString, xmlString.Length, signId, certificate, ref certificateLength);
        ThrowIfError(errorCode);
        return certificate.ToString();
    }

    public string GetSignatureAlgrithmFromXml(string? xmlString)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (xmlString is null)
        {
            throw new ArgumentNullException(nameof(xmlString));
        }

        var certificateLength = 0;
        var errorCode = StKCFunctionsType.KC_getSigAlgFromXML(xmlString, xmlString.Length, null, ref certificateLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var certificate = new StringBuilder(certificateLength);
        errorCode = StKCFunctionsType.KC_getSigAlgFromXML(xmlString, xmlString.Length, certificate, ref certificateLength);
        ThrowIfError(errorCode);
        return certificate.ToString();
    }

    private void EnsureKeyStoreLoaded()
    {
        if (!keyStoreLoaded)
        {
            throw new InvalidOperationException("Key store is not loaded");
        }
    }

    private static void EnsureInitialized()
    {
        if (!initialized)
        {
            throw new InvalidOperationException("The Kalcancrypt was not initialized");
        }
    }

    private static void ThrowIfError(KalkanError errorCode)
    {
        if (errorCode == 0)
        {
            return;
        }

        int size = 0;
        var conversionErrorCode = StKCFunctionsType.KC_GetLastErrorString(null, ref size);
        if (conversionErrorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            throw new InvalidOperationException(string.Format("Fatal error during reading message for error code: {0}. Error code from conversion procedure is: {1}", errorCode, conversionErrorCode));
        }

        var err = new StringBuilder(size);
        conversionErrorCode = StKCFunctionsType.KC_GetLastErrorString(err, ref size);
        if (conversionErrorCode != 0 && conversionErrorCode != errorCode)
        {
            throw new InvalidOperationException(string.Format("Fatal error during reading message for error code: {0}. Error code from conversion procedure is: {1}", errorCode, conversionErrorCode));
        }

        throw new InvalidOperationException(err.ToString());
    }

    private static KalkanSignFlags SignFlags(KalkanSignType signType, KalkanInputFormat inputFormat,
        KalkanOutputFormat outputFormat)
    {
        KalkanSignFlags flags = default;
        switch (signType)
        {
            case KalkanSignType.Draft:
                flags |= KalkanSignFlags.SignDraft;
                break;
            case KalkanSignType.Cms:
                flags |= KalkanSignFlags.SignCms;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(signType));
        }

        switch (inputFormat)
        {
            case KalkanInputFormat.Der:
                flags |= KalkanSignFlags.InputDer;
                break;
            case KalkanInputFormat.Pem:
                flags |= KalkanSignFlags.InputPem;
                break;
            case KalkanInputFormat.Base64:
                flags |= KalkanSignFlags.InputBase64;
                break;
            case KalkanInputFormat.Base64Variant2:
                flags |= KalkanSignFlags.Input2Base64;
                break;
            case KalkanInputFormat.File:
                flags |= KalkanSignFlags.InputFile;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(inputFormat));
        }

        switch (outputFormat)
        {
            case KalkanOutputFormat.Der:
                flags |= KalkanSignFlags.OutputDer;
                break;
            case KalkanOutputFormat.Pem:
                flags |= KalkanSignFlags.OutputPem;
                break;
            case KalkanOutputFormat.Base64:
                flags |= KalkanSignFlags.OutputBase64;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(outputFormat));
        }

        return flags;
    }
}