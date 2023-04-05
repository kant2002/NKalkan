using System.Runtime.InteropServices;
using System.Text;

namespace NKalcan;

public sealed class KalkanApi
{
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

    public void LoadKeyStore(KalkanStorageType storeType, string containerPath, string password, string? alias = null)
    {
        EnsureInitialized();
        var errCode = StKCFunctionsType.KC_LoadKeyStore((int)storeType, password, password.Length, containerPath, containerPath.Length, alias);
        ThrowIfError(errCode);

        keyStoreLoaded = true;
    }

    public string SignXml(string content, string? alias = null, string? signNodeId = null, string? parentSignNode = null, string parentNameSpace = "")
    {
        EnsureInitialized();
        EnsureKeyStoreLoaded();
        if (parentNameSpace is null)
        {
            throw new ArgumentNullException(nameof(parentNameSpace));
        }

        var signedPayloadLength = 0;
        var errorCode = StKCFunctionsType.SignXML(alias, 0, content, content.Length, null, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        if (errorCode != KalkanError.BUFFER_TOO_SMALL)
        {
            ThrowIfError(errorCode);
        }

        var signedPayload = new StringBuilder(signedPayloadLength);
        errorCode = StKCFunctionsType.SignXML(alias, 0, content, content.Length, signedPayload, ref signedPayloadLength, signNodeId, parentSignNode, parentNameSpace);
        ThrowIfError(errorCode);
        return signedPayload.ToString();
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