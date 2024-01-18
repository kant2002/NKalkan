namespace NKalkan;

public enum KalkanValidationType
{
    Nothing = 0x00000401,
    Crl = 0x00000402,
    // FIx: Attempted to read or write protected memory. This is often an indication that other memory is corrupt
    Ocsp = 0x00000404,
}
