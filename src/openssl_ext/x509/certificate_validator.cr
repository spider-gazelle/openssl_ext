require "./certificate"

module OpenSSL::X509
  class CertificateValidationError < X509Error
    getter error_code : Int32
    getter error_depth : Int32
    getter error_message : String

    def initialize(@error_code, @error_depth, @error_message)
      super("Certificate validation failed at depth #{@error_depth}: #{@error_message} (code: #{@error_code})")
    end
  end

  # Certificate chain validator using OpenSSL's X509_STORE
  class CertificateValidator
    @store : LibCrypto::X509_STORE

    def initialize
      @store = LibCrypto.x509_store_new
      raise X509Error.new("Failed to create X509_STORE") if @store.null?
    end

    def finalize
      LibCrypto.x509_store_free(@store) unless @store.null?
    end

    # Add a trusted root certificate to the certificate store
    def add_trusted_cert(cert : Certificate)
      result = LibCrypto.x509_store_add_cert(@store, cert)
      raise X509Error.new("Failed to add certificate to store") if result != 1
    end

    # Add multiple trusted root certificates
    def add_trusted_certs(certs : Array(Certificate))
      certs.each { |cert| add_trusted_cert(cert) }
    end

    # Set verification flags
    # Available flags:
    # - LibCrypto::X509_V_FLAG_USE_CHECK_TIME
    # - LibCrypto::X509_V_FLAG_CRL_CHECK
    # - LibCrypto::X509_V_FLAG_CRL_CHECK_ALL
    # - LibCrypto::X509_V_FLAG_IGNORE_CRITICAL
    # - LibCrypto::X509_V_FLAG_X509_STRICT
    # - LibCrypto::X509_V_FLAG_PARTIAL_CHAIN
    def flags=(flags : UInt64)
      result = LibCrypto.x509_store_set_flags(@store, flags)
      raise X509Error.new("Failed to set store flags") if result != 1
    end

    # Verify a certificate chain
    # @param cert The end-entity certificate to verify
    # @param chain Optional array of intermediate certificates
    # @return true if the certificate is valid
    # @raise CertificateValidationError if validation fails
    def verify(cert : Certificate, chain : Array(Certificate)? = nil) : Bool
      ctx = LibCrypto.x509_store_ctx_new
      raise X509Error.new("Failed to create X509_STORE_CTX") if ctx.null?

      begin
        # Initialize the verification context
        result = LibCrypto.x509_store_ctx_init(ctx, @store, cert, nil)
        raise X509Error.new("Failed to initialize store context") if result != 1

        # Perform the verification
        result = LibCrypto.x509_verify_cert(ctx)

        if result == 1
          # Verification successful
          true
        else
          # Verification failed - get error details
          error_code = LibCrypto.x509_store_ctx_get_error(ctx)
          error_depth = LibCrypto.x509_store_ctx_get_error_depth(ctx)
          error_msg_ptr = LibCrypto.x509_verify_cert_error_string(error_code.to_i64)
          error_msg = error_msg_ptr ? String.new(error_msg_ptr) : "Unknown error"

          raise CertificateValidationError.new(error_code, error_depth, error_msg)
        end
      ensure
        LibCrypto.x509_store_ctx_free(ctx)
      end
    end

    # Verify a certificate chain without raising exceptions
    # Returns a tuple: {success: Bool, error_code: Int32?, error_message: String?}
    def verify_safe(cert : Certificate, chain : Array(Certificate)? = nil)
      ctx = LibCrypto.x509_store_ctx_new
      return {success: false, error_code: -1, error_message: "Failed to create context"} if ctx.null?

      begin
        result = LibCrypto.x509_store_ctx_init(ctx, @store, cert, nil)
        return {success: false, error_code: -1, error_message: "Failed to initialize context"} if result != 1

        result = LibCrypto.x509_verify_cert(ctx)

        if result == 1
          {success: true, error_code: nil, error_message: nil}
        else
          error_code = LibCrypto.x509_store_ctx_get_error(ctx)
          error_depth = LibCrypto.x509_store_ctx_get_error_depth(ctx)
          error_msg_ptr = LibCrypto.x509_verify_cert_error_string(error_code.to_i64)
          error_msg = error_msg_ptr ? String.new(error_msg_ptr) : "Unknown error"

          {success: false, error_code: error_code, error_message: "#{error_msg} at depth #{error_depth}"}
        end
      ensure
        LibCrypto.x509_store_ctx_free(ctx)
      end
    end

    # Verify that a certificate was signed by another certificate (issuer)
    # This does NOT perform full chain validation, just signature verification
    def self.verify_signed_by(cert : Certificate, issuer : Certificate) : Bool
      issuer_pubkey = issuer.public_key
      cert.verify(issuer_pubkey)
    end

    # Check if a certificate is self-signed
    def self.self_signed?(cert : Certificate) : Bool
      # A certificate is self-signed if issuer equals subject
      # and it's signed with its own public key

      # Compare issuer and subject by converting to arrays
      issuer_array = cert.issuer.to_a
      subject_array = cert.subject.to_a

      return false if issuer_array != subject_array

      begin
        pubkey = cert.public_key
        cert.verify(pubkey)
      rescue
        false
      end
    end

    # Validate certificate time validity
    def self.valid_at?(cert : Certificate, time : Time = Time.utc) : Bool
      cert.not_before <= time && time <= cert.not_after
    end

    # Get human-readable error message for an error code
    def self.error_string(error_code : Int32) : String
      error_msg_ptr = LibCrypto.x509_verify_cert_error_string(error_code.to_i64)
      error_msg_ptr ? String.new(error_msg_ptr) : "Unknown error (#{error_code})"
    end
  end
end
