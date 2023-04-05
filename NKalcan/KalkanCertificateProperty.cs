namespace NKalcan;

public enum KalkanCertificateProperty
{
	IssuerCountryName		= 0x00000801,
	IssuerSOPN				= 0x00000802,
	IssuerLocalityName		= 0x00000803,
	IssuerOrganizationName	= 0x00000804,
    IssuerOrganizationUnitName = 0x00000805,
	IssuerCommonName		= 0x00000806,

    SubjectCountryName		= 0x00000807,
	SubjectSOPN				= 0x00000808,
    SubjectLocalityName		= 0x00000809,
    SubjectCommonName		= 0x0000080a,
	SubjectGivenName		= 0x0000080b,
	SubjectSurname			= 0x0000080c,
	SubjectSerialNumber		= 0x0000080d,
	SubjectEmail			= 0x0000080e,
    SubjectOrganizationName = 0x0000080f,
    SubjectOrganizationUnitName = 0x00000810,
	SubjectBC				= 0x00000811,
	SubjectDC				= 0x00000812,
											   
	NotBefore				= 0x00000813,
	NotAfter				= 0x00000814,
											   
	KeyUsage				= 0x00000815,
	ExtendedKetUsage		= 0x00000816,
											   
	AuthorityKeyId			= 0x00000817,
	SubjectKeyId			= 0x00000818,
	CertificateSN			= 0x00000819,

    IssuerDN				= 0x0000081a,
    SubjectDN				= 0x0000081b,
											   
	SignatureAlgorithm		= 0x0000081c,
	
	PublicKey				= 0x0000081d,
	
	PoliciesId				= 0x0000081e,
	OCSP					= 0x0000081f,
	GET_CRL					= 0x00000820,
	GET_DELTA_CRL			= 0x00000821,
}
