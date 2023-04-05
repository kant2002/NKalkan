namespace NKalcan;

public enum KalkanSignFlags
{
    SignDraft		= 0x00000001,
    SignCms		    = 0x00000002,
    InputPem		= 0x00000004,
    InputDer    	= 0x00000008,
    InputBase64		= 0x00000010,
    Input2Base64	= 0x00000020,
    DetachedData	= 0x00000040,
    WithCertificate	= 0x00000080,
    WithTimestamp	= 0x00000100,
    OutputPem		= 0x00000200,
    OutputDer		= 0x00000400,
    OutputBase64	= 0x00000800,
    ProxyOff		= 0x00001000,
    ProxyOn	    	= 0x00002000,
    ProxyAuth		= 0x00004000,
    InputFile		= 0x00008000,
    DoNotCheckCertificateTime	= 0x00010000,
    HashSha256		= 0x00020000,
    HashGost95		= 0x00040000,
}
