using System;
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

    public string SignXml(string content, KalkanSignFlags flags = 0, string? certificateAlias = null, string? signNodeId = null, string? parentSignNode = null, string parentNameSpace = "")
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (parentNameSpace is null)
        {
            throw new ArgumentNullException(nameof(parentNameSpace));
        }

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.SignXML(certificateAlias, (int)flags, content, content.Length, null, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.SignXML(certificateAlias, (int)flags, content, content.Length, signedPayload, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
    }

    public string VerifyXml(string content, KalkanSignFlags flags = 0, string? certificateAlias = null)
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.VerifyXML(certificateAlias, (int)flags, content, content.Length, null, ref signedPayloadLength);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.VerifyXML(certificateAlias, (int)flags, content, content.Length, signedPayload, ref signedPayloadLength);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
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
}