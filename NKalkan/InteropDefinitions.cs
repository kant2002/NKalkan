using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NKalkan;

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
internal delegate KalkanError KC_getCertFromXML(string? inXml, int inXmlLength, int inSignId, StringBuilder? outCertificate, ref int outCertificateLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_getSigAlgFromXML(string? inXml, int inXmlLength, StringBuilder? signAlgorithm, ref int signAlgorithmLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_SignData(string? alias, int flags, byte[] inData, int inDataLength, string? inSign, int inSignLength, StringBuilder? outSign, ref int outSignoutSignLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_VerifyData(string? alias, int flags, byte[] inData, int inDataLength, string inoutSign, int inoutSignLength, 
    StringBuilder? outData, ref int outDataLength, StringBuilder? outVerifyInfo, ref int outVerifyInfoLength, int inCertID, StringBuilder? outCert, ref int outCertLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509LoadCertificateFromFile(string certificatePath, int certificateType);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509ExportCertificateFromStore(string? alias, int flags, StringBuilder certificateData, ref int certificateDataLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509CertificateGetInfo(string certificateData, int certificateDataLength, int propertyId, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder certificatePropertyData, ref int certificatePropertyDataLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_X509ValidateCertificate(string certificateData, int certificateDataLength, int validType, [MarshalAs(UnmanagedType.LPUTF8Str)] string validPath, long checkTime, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder? outputInformation, ref int outputInformationLength, int flag, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder? ocsPResponse, ref int ocsPResponseLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_SignWSSE(string? alias, int flags, byte[] inData, int inDataLength, byte[] outSign, ref int outSignoutSignLength, string? signNodeId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate KalkanError KC_HashData(string? algorithm, int flags, byte[] inData, int inDataLength, StringBuilder? outSign, ref int outSignoutSignLength);

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
    public KC_X509ValidateCertificate X509ValidateCertificate;
    public KC_HashData HashData;
    public KC_HashData SignHash;
    public KC_SignData SignData;
    public KC_SignXML SignXML;
    public KC_VerifyData VerifyData;
    public KC_VerifyXML VerifyXML;
    public KC_getCertFromXML KC_getCertFromXML;
    public KC_getSigAlgFromXML KC_getSigAlgFromXML;
    public KC_GetLastError KC_GetLastError;
    public KC_GetLastErrorString KC_GetLastErrorString;
    public delegate* unmanaged[Cdecl]<void> KC_XMLFinalize;
    public delegate* unmanaged[Cdecl]<void> KC_Finalize;
    public IntPtr KC_TSASetUrl;
    public IntPtr KC_GetTimeFromSig;
    public IntPtr KC_SetProxy;
    public IntPtr KC_GetCertFromCMS;
    public KC_SignWSSE SignWSSE;
    public IntPtr ZipConVerify;
    public IntPtr ZipConSign;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FunctionsType
{
    public IntPtr stKCFunctionsType;
}
