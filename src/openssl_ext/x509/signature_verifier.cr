require "./certificate"
require "../pkey/pkey"

module OpenSSL::X509
  class SignatureVerificationError < X509Error; end

  # Utilities for verifying signatures using X.509 certificates
  module SignatureVerifier
    # Verify a signature over data using a certificate's public key
    # @param data The data that was signed
    # @param signature The signature bytes
    # @param cert The certificate containing the public key
    # @param digest_type The digest algorithm used (default: SHA256)
    # @return true if signature is valid, false otherwise
    def self.verify_signature(
      data : Bytes,
      signature : Bytes,
      cert : Certificate,
      digest_type : OpenSSL::Algorithm = :SHA256,
    ) : Bool
      pubkey = cert.public_key
      verify_signature(data, signature, pubkey, digest_type)
    end

    # Verify a signature over data using a public key
    # @param data The data that was signed
    # @param signature The signature bytes
    # @param pubkey The public key to verify with
    # @param digest_type The digest algorithm used (default: SHA256)
    # @return true if signature is valid, false otherwise
    def self.verify_signature(
      data : Bytes,
      signature : Bytes,
      pubkey : OpenSSL::PKey::PKey,
      digest_type : OpenSSL::Algorithm = :SHA256,
    ) : Bool
      # Compute digest of the data
      digest = OpenSSL::Digest.new(digest_type.to_s)
      digest.update(data)
      hash = digest.final

      # Verify the signature
      verify_digest_signature(hash, signature, pubkey)
    end

    # Verify a signature over an already-computed digest
    # @param digest The digest bytes
    # @param signature The signature bytes
    # @param pubkey The public key to verify with
    # @return true if signature is valid, false otherwise
    def self.verify_digest_signature(
      digest : Bytes,
      signature : Bytes,
      pubkey : OpenSSL::PKey::PKey,
    ) : Bool
      case pubkey
      when OpenSSL::PKey::EC
        # For EC keys, use ECDSA verification
        pubkey.ec_verify(digest, signature)
      when OpenSSL::PKey::RSA
        # For RSA keys, use RSA verification with PKCS1 padding
        # First decrypt the signature to get the digest
        begin
          decrypted = pubkey.public_decrypt(signature)
          # Compare the decrypted digest with our computed digest
          decrypted == digest
        rescue
          false
        end
      else
        # Use generic EVP verification
        begin
          # Pending!
          # This is a simplified check - real implementation would use EVP_MD_CTX
          # For now, we'll return false for unsupported key types
          false
        rescue
          false
        end
      end
    end

    # Verify a signature over data using a certificate's public key (raises on error)
    # @param data The data that was signed
    # @param signature The signature bytes
    # @param cert The certificate containing the public key
    # @param digest_type The digest algorithm used (default: SHA256)
    # @raise SignatureVerificationError if verification fails
    def self.verify_signature!(
      data : Bytes,
      signature : Bytes,
      cert : Certificate,
      digest_type : OpenSSL::Algorithm = :SHA256,
    )
      unless verify_signature(data, signature, cert, digest_type)
        raise SignatureVerificationError.new("Signature verification failed")
      end
    end

    # Extract the signature value from a certificate
    # This is useful for debugging or analyzing certificate signatures
    # @return The raw signature bytes from the certificate
    def self.extract_signature(cert : Certificate) : Bytes?
      sig_ptr = Pointer(LibC::Char).null
      alg_ptr = Pointer(LibCrypto::X509_ALGOR).null

      LibCrypto.x509_get0_signature(pointerof(sig_ptr), pointerof(alg_ptr), cert)

      return nil if sig_ptr.null?

      # The signature is stored as an ASN1_BIT_STRING
      # We need to extract the actual bytes
      # For now, return nil as this requires more ASN.1 parsing
      nil
    rescue
      nil
    end

    # Verify that a certificate was signed by an issuer certificate
    # This verifies the certificate's own signature using the issuer's public key
    # @param cert The certificate to verify
    # @param issuer The issuing certificate
    # @return true if the certificate was signed by the issuer
    def self.verify_issued_by(cert : Certificate, issuer : Certificate) : Bool
      issuer_pubkey = issuer.public_key
      cert.verify(issuer_pubkey)
    rescue
      false
    end

    # Build and verify a certificate chain
    # @param leaf The end-entity certificate
    # @param intermediates Array of intermediate certificates
    # @param root The root certificate
    # @return true if the chain is valid
    def self.verify_chain(
      leaf : Certificate,
      intermediates : Array(Certificate),
      root : Certificate,
    ) : Bool
      # Verify each certificate in the chain
      current = leaf

      intermediates.each do |intermediate|
        return false unless verify_issued_by(current, intermediate)
        current = intermediate
      end

      # Verify the last intermediate was signed by the root
      verify_issued_by(current, root)
    rescue
      false
    end
  end
end
