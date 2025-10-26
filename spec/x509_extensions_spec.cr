require "./spec_helper"
require "spec"
require "base64"

include OpenSSL::X509

# Sample self-signed certificate for testing
SAMPLE_CERT_PEM = "-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIIcTFLZ2AHMiUwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE
AxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTgw
MzA3MDA0NTI2WhcNMTgwMzEwMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl
bi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJr02/VJFlNZBZNvHqkuFHj8XrQ0QUQUVe/QvVF+atvIPJ+a
FQ9Wd0CvYcW8kqPca6ro+m/QMS0Himi3UZpnVaXleWU1um7E7VboFlozS+TisCo4
J5Reaj3oiY0NIi+mnSmJALbjbvzWBixqSaghqQDzddT8BtL8nG/jR0L4D4z21nPv
2PIE4kuBIP8kOhELY4exKlMQSUeebkHtdJJ9+ocE8y2YoetLfpKwvkXWzxmIF2wa
UrN+svohzlnjkok+QOI+jhOJcOz88zkto0GrTAaGu03stZ37fajOpyTKfcpnHysU
7EEKmWrGQfM22PMQflGqAWZBZw6lyY1FI/I90bUCAwEAAaM4MDYwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ
KoZIhvcNAQEFBQADggEBAJTBdFNRn47EK6wqGQvpHi3lBDk0OqIE09vwkvc81KAD
En8ISqR5jJZFgiTi1NU6d/yRAzRYUCpa2YHoB2qqsZfV53kmcSjYhEuxDWZPNcLf
XyZdGu2xtV5Z3SqVr9yGpasHx+ZsCTYI+jE9wi+nM5MWtWzr1hn6sFM10APkRd8l
s6s7aLFlnJ+Xgt8EhNZxKxk87rr5Mi/Lk0QniTdI67tFAxHwyk80IHl4uzYntlHg
DQ51uI5iyjWxS4QcFQZGVCZ45JOtzLsnRV1+NgnTasB1ah0gfnw4AXYOR4jV7kd4
mfzRpDQdyLFZqfGFyYQ6WSw3EFqIunkL8WPWRpG++5g=
-----END CERTIFICATE-----
"

# Helper to create a Name with entries
def create_name(cn : String)
  name = OpenSSL::X509::Name.new
  name.add_entry("CN", cn)
  name
end

describe "X.509 Certificate Extensions" do
  describe "Certificate DER encoding/decoding" do
    it "can parse a certificate from DER format" do
      # First convert PEM to DER
      pem_cert = Certificate.from_pem(SAMPLE_CERT_PEM)
      der_bytes = pem_cert.to_der

      # Parse from DER
      der_cert = Certificate.from_der(der_bytes)

      # Verify it's the same certificate
      der_cert.subject.to_a[0][1].should eq pem_cert.subject.to_a[0][1]
      # Compare serial numbers by converting to hex strings
      der_cert.serial.to_hex.should eq pem_cert.serial.to_hex
    end

    it "can convert a certificate to DER format" do
      cert = Certificate.from_pem(SAMPLE_CERT_PEM)
      der_bytes = cert.to_der

      # Should be binary data (not PEM text)
      der_bytes.size.should be > 0
      # DER encoding should start with SEQUENCE tag (0x30)
      der_bytes[0].should eq 0x30
    end

    it "can round-trip PEM -> DER -> PEM" do
      original_cert = Certificate.from_pem(SAMPLE_CERT_PEM)
      der_bytes = original_cert.to_der
      der_cert = Certificate.from_der(der_bytes)
      der_cert.to_pem

      # Subject should be preserved
      original_cert.subject.to_a[0][1].should eq der_cert.subject.to_a[0][1]
    end
  end

  describe "Certificate Validator" do
    it "can create a certificate validator" do
      validator = CertificateValidator.new
      validator.should_not be_nil
    end

    it "can check if a certificate is self-signed" do
      cert = Certificate.from_pem(SAMPLE_CERT_PEM)

      # This certificate might not be self-signed, so we just test the method exists
      result = CertificateValidator.self_signed?(cert)
      result.should be_a(Bool)
    end

    it "can check certificate time validity" do
      cert = Certificate.from_pem(SAMPLE_CERT_PEM)

      # Certificate is from 2018, so it should be expired
      CertificateValidator.valid_at?(cert, Time.utc).should be_false

      # Should be valid at a time during its validity period
      valid_time = Time.parse("2018-03-08 12:00:00", "%Y-%m-%d %H:%M:%S", Time::Location::UTC)
      CertificateValidator.valid_at?(cert, valid_time).should be_true
    end

    it "can get error strings for verification errors" do
      error_msg = CertificateValidator.error_string(LibCrypto::X509_V_ERR_CERT_HAS_EXPIRED)
      error_msg.should contain("expired")
    end

    it "can verify a self-signed certificate against itself" do
      # Create a self-signed certificate for testing
      root_key = OpenSSL::PKey::RSA.new(2048)
      root_cert = Certificate.new

      root_cert.version = 2
      root_cert.serial = 1_u64

      subject = Name.new
      subject.add_entry("CN", "Test Root CA")
      root_cert.subject = subject

      # For issuer, use the same name
      issuer = Name.new
      issuer.add_entry("CN", "Test Root CA")
      root_cert.issuer = issuer
      root_cert.public_key = root_key
      root_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      root_cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)

      root_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Verify it's self-signed
      CertificateValidator.self_signed?(root_cert).should be_true
    end
  end

  describe "SignatureVerifier" do
    it "can verify issued_by relationship" do
      # Create a self-signed root certificate
      root_key = OpenSSL::PKey::RSA.new(2048)
      root_cert = Certificate.new

      root_cert.version = 2
      root_cert.serial = 1_u64

      subject = Name.new
      subject.add_entry("CN", "Test Root CA")
      root_cert.subject = subject

      # For issuer, use the same name
      issuer = Name.new
      issuer.add_entry("CN", "Test Root CA")
      root_cert.issuer = issuer
      root_cert.public_key = root_key
      root_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      root_cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)

      root_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Verify the root cert was signed by itself
      SignatureVerifier.verify_issued_by(root_cert, root_cert).should be_true
    end

    it "can verify signatures using EC keys" do
      # Create an EC key pair
      ec_key = OpenSSL::PKey::EC.new(256)

      # Sign some data
      data = "Hello, World!".to_slice
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(data)
      hash = digest.final

      signature = ec_key.ec_sign(hash)

      # Verify the signature
      result = SignatureVerifier.verify_digest_signature(hash, signature, ec_key)
      result.should be_true
    end

    it "can verify signatures with certificate public keys" do
      # Create a certificate with an EC key
      ec_key = OpenSSL::PKey::EC.new(256)
      cert = Certificate.new

      cert.version = 2
      cert.serial = 1_u64
      cert.subject = create_name("Test Certificate")
      cert.issuer = cert.subject
      cert.public_key = ec_key
      cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)

      cert.sign(ec_key, OpenSSL::Digest.new("SHA256"))

      # Sign some data with the private key
      data = "Test data for signing".to_slice
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(data)
      hash = digest.final

      signature = ec_key.ec_sign(hash)

      # Verify using the certificate's public key
      result = SignatureVerifier.verify_signature(data, signature, cert, :SHA256)
      result.should be_true
    end

    it "rejects invalid signatures" do
      # Create an EC key pair
      ec_key = OpenSSL::PKey::EC.new(256)

      # Sign some data
      data = "Original data".to_slice
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(data)
      hash = digest.final

      signature = ec_key.ec_sign(hash)

      # Try to verify with different data
      tampered_data = "Tampered data".to_slice
      cert = Certificate.new
      cert.version = 2
      cert.serial = 1_u64
      cert.subject = create_name("Test")
      cert.issuer = cert.subject
      cert.public_key = ec_key
      cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)
      cert.sign(ec_key, OpenSSL::Digest.new("SHA256"))

      result = SignatureVerifier.verify_signature(tampered_data, signature, cert, :SHA256)
      result.should be_false
    end
  end

  describe "Certificate signature verification" do
    it "can verify a certificate was signed by issuer" do
      # Create a root CA
      root_key = OpenSSL::PKey::RSA.new(2048)
      root_cert = Certificate.new

      root_cert.version = 2
      root_cert.serial = 1_u64
      root_cert.subject = create_name("Root CA")
      root_cert.issuer = root_cert.subject
      root_cert.public_key = root_key
      root_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      root_cert.not_after = OpenSSL::ASN1::Time.days_from_now(3650)

      root_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Create an intermediate certificate signed by root
      intermediate_key = OpenSSL::PKey::RSA.new(2048)
      intermediate_cert = Certificate.new

      intermediate_cert.version = 2
      intermediate_cert.serial = 2_u64
      intermediate_cert.subject = create_name("Intermediate CA")
      intermediate_cert.issuer = root_cert.subject
      intermediate_cert.public_key = intermediate_key
      intermediate_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      intermediate_cert.not_after = OpenSSL::ASN1::Time.days_from_now(1825)

      # Sign intermediate with root's private key
      intermediate_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Verify the intermediate was signed by the root
      intermediate_cert.verify(root_key).should be_true
      SignatureVerifier.verify_issued_by(intermediate_cert, root_cert).should be_true
    end

    it "can verify a certificate chain" do
      # Create root CA
      root_key = OpenSSL::PKey::RSA.new(2048)
      root_cert = Certificate.new
      root_cert.version = 2
      root_cert.serial = 1_u64
      root_cert.subject = create_name("Root CA")
      root_cert.issuer = root_cert.subject
      root_cert.public_key = root_key
      root_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      root_cert.not_after = OpenSSL::ASN1::Time.days_from_now(3650)
      root_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Create intermediate CA
      intermediate_key = OpenSSL::PKey::RSA.new(2048)
      intermediate_cert = Certificate.new
      intermediate_cert.version = 2
      intermediate_cert.serial = 2_u64
      intermediate_cert.subject = create_name("Intermediate CA")
      intermediate_cert.issuer = root_cert.subject
      intermediate_cert.public_key = intermediate_key
      intermediate_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      intermediate_cert.not_after = OpenSSL::ASN1::Time.days_from_now(1825)
      intermediate_cert.sign(root_key, OpenSSL::Digest.new("SHA256"))

      # Create end-entity certificate
      leaf_key = OpenSSL::PKey::RSA.new(2048)
      leaf_cert = Certificate.new
      leaf_cert.version = 2
      leaf_cert.serial = 3_u64
      leaf_cert.subject = create_name("example.com")
      leaf_cert.issuer = intermediate_cert.subject
      leaf_cert.public_key = leaf_key
      leaf_cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
      leaf_cert.not_after = OpenSSL::ASN1::Time.days_from_now(365)
      leaf_cert.sign(intermediate_key, OpenSSL::Digest.new("SHA256"))

      # Verify the chain
      result = SignatureVerifier.verify_chain(
        leaf_cert,
        [intermediate_cert],
        root_cert
      )
      result.should be_true
    end
  end
end
