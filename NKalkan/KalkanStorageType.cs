namespace NKalkan;

public enum KalkanStorageType
{
    /// <summary>
    /// Represents the container storage in file of PKCS12 format.
    /// </summary>
    PKCS12 = 1,

    /// <summary>
    /// Represents storage in the identity card citizen of Kazakhstan.
    /// </summary>
    KZIDCard = 2,

    /// <summary>
    /// Represents the container storage in Kaztoken
    /// </summary>
    KazToken = 4,

    /// <summary>
    /// Represents the container storage in eToken 72k
    /// </summary>
    EToken = 8,

    /// <summary>
    /// Represents the container storage in JaCarta
    /// </summary>
    JaCarta = 16,

    /// <summary>
    /// Represents container storage in X509 certificate
    /// </summary>
    X509Cert = 32,

    /// <summary>
    /// Represents container storage in aKey
    /// </summary>
    AKey = 64,

    /// <summary>
    /// Represents container storage in eToken 5110
    /// </summary>
    EToken5110 = 128,

}
