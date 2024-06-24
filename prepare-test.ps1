$SdkLocation="C:\d\prog\kalkan\SDK 2024-04-30"
$TargetFrameworkVersion="net8.0"
$Configuration="Debug"
$TargetLocation="NKalkan.TestBed\bin\$Configuration\$TargetFrameworkVersion"
dotnet build
Copy-Item "$SdkLocation\C\Windows\KalkanCrypt_С\lib\x64\KalkanCrypt.dll" "$TargetLocation\KalkanCrypt.dll"
Copy-Item "$SdkLocation\C\Linux\C\test\example\test_CERT_GOST.txt" "$TargetLocation\test_CERT_GOST.txt"
Copy-Item "$SdkLocation\C\Linux\C\test\example\test_CMS_GOST.txt" "$TargetLocation\test_CMS_GOST.txt"
Copy-Item "$SdkLocation\Keys and Certs\Gost2004 and RSA\2023.11.17_valid\Физическое лицо\valid\AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12" "$TargetLocation\AUTH_RSA256_df5e58a1d8998ac28a8409ef1d9c7f41dfdbd114.p12"
# Keys and Certs\CA_Test\ROOT\kuc_rsa_test.cer Manually in the Truster Certificates Root
# Keys and Certs\CA_Test\NCA\nca_rsa_test.cer Can be automatically imported

# Keys and Certs\CA_Test\ROOT\kuc_rsa_test.cer Manually in the Truster Certificates Root
# Keys and Certs\CA_Test\NCA\nca_rsa_test.cer Can be automatically imported
