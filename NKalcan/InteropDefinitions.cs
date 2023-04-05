using System.Runtime.InteropServices;
using System.Text;

namespace NKalcan;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_GetLastError();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_GetLastErrorString(StringBuilder? errorString, ref int bufSize);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_LoadKeyStore(int storage, string password, int passLen, string container, int containerLen, string? alias);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_SignXML(string? alias, int flags, string inData, int inDataLength, StringBuilder? outSign, ref int outSignoutSignLength, string? signNodeId, string? parentSignNode, string? parentNameSpace);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_VerifyXML(string? alias, int flags, string inData, int inDataLength, StringBuilder? outVerifyInfo, ref int outVerifyInfoLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_SignData(string? alias, int flags, byte[] inData, int inDataLength, string inSign, int inSignLength, StringBuilder? outSign, ref int outSignoutSignLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_VerifyData(string? alias, int flags, byte[] inData, int inDataLength, string inoutSign, int inoutSignLength, 
    StringBuilder? outData, ref int outDataLength, StringBuilder? outVerifyInfo, ref int outVerifyInfoLength, int inCertID, StringBuilder? outCert, ref int outCertLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509LoadCertificateFromFile(string certificatePath, int certificateType);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509ExportCertificateFromStore(string? alias, int flags, StringBuilder certificateData, ref int certificateDataLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509CertificateGetInfo(string certificateData, int certificateDataLength, int propertyId, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder certificatePropertyData, ref int certificatePropertyDataLength);

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct StKCFunctionsType
{
    public delegate* unmanaged[Cdecl]<KalkanError> KC_Init;
    public IntPtr KC_GetTokens;
    public IntPtr KC_GetCertificatesList;
    public KC_LoadKeyStore KC_LoadKeyStore;
    public delegate* unmanaged[Cdecl]<IntPtr, int, KalkanError> X509LoadCertificateFromFile;
    public IntPtr X509LoadCertificateFromBuffer;
    public KC_X509ExportCertificateFromStore X509ExportCertificateFromStore;
    public KC_X509CertificateGetInfo X509CertificateGetInfo;
    public IntPtr X509ValidateCertificate;
    public IntPtr HashData;
    public IntPtr SignHash;
    public KC_SignData SignData;
    public KC_SignXML SignXML;
    public KC_VerifyData VerifyData;
    public KC_VerifyXML VerifyXML;
    public IntPtr KC_getCertFromXML;
    public IntPtr KC_getSigAlgFromXML;
    public KC_GetLastError KC_GetLastError;
    public KC_GetLastErrorString KC_GetLastErrorString;
    public IntPtr KC_XMLFinalize;
    public IntPtr KC_Finalize;
    public IntPtr KC_TSASetUrl;
    public IntPtr KC_GetTimeFromSig;
    public IntPtr KC_SetProxy;
    public IntPtr KC_GetCertFromCMS;
    public IntPtr SignWSSE;
    public IntPtr ZipConVerify;
    public IntPtr ZipConSign;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FunctionsType
{
    public IntPtr stKCFunctionsType;
}
