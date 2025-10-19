require "./pkey"

module OpenSSL::PKey
  class RsaError < PKeyError; end

  class RSA < PKey
    @blinding_on : Bool = false

    def self.new(encoded : String, passphrase = nil)
      self.new(IO::Memory.new(encoded), passphrase)
    end

    def self.new(io : IO, passphrase = nil)
      content = Bytes.new(io.size)
      io.read(content)
      io.rewind

      priv = true

      cb, cb_u = OpenSSL::PKey.passphrase_callback(passphrase)

      bio = GETS_BIO.new(io)
      rsa_key = LibCrypto.pem_read_bio_rsa_private_key(bio, nil, cb, cb_u)
      io.rewind

      if rsa_key.null?
        begin
          decoded = Base64.decode(content)
          buf = IO::Memory.new(decoded)

          bio = GETS_BIO.new(buf)
          rsa_key = LibCrypto.d2i_rsa_private_key_bio(bio, nil)
        rescue Base64::Error
        end
      end

      if rsa_key.null?
        bio = GETS_BIO.new(io)
        rsa_key = LibCrypto.pem_read_bio_rsa_public_key(bio, nil, cb, cb_u)
        priv = false unless rsa_key.null?
        io.rewind
      end

      if rsa_key.null?
        bio = GETS_BIO.new(io)
        rsa_key = LibCrypto.pem_read_bio_rsa_pubkey(bio, nil, cb, cb_u)
        priv = false unless rsa_key.null?
        io.rewind
      end

      if rsa_key.null?
        raise RsaError.new "Neither PUB or PRIV key"
      end

      new(priv).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_RSA, rsa_key.as Pointer(Void))
      end
    end

    def self.new(size : Int32)
      exponent = 65537.to_u32
      self.generate(size, exponent)
    end

    def self.generate(size : Int32, exponent : UInt32)
      rsa_pointer = LibCrypto.rsa_new

      exponent_bn = OpenSSL::BN.from_dec(exponent.to_s)
      LibCrypto.rsa_generate_key_ex(rsa_pointer, size, exponent_bn, nil)

      new(true).tap do |pkey|
        LibCrypto.evp_pkey_set1_rsa(pkey, rsa_pointer)
      end
    end

    private def rsa
      LibCrypto.evp_pkey_get1_rsa(self)
    end

    def public_key
      pub_rsa = LibCrypto.rsa_public_key_dup(rsa)
      raise RsaError.new "Could not get public key from RSA" unless pub_rsa

      RSA.new(false).tap do |pkey|
        LibCrypto.evp_pkey_set1_rsa(pkey, pub_rsa)
      end
    end

    def public_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      if max_encrypt_size < from.size
        raise RsaError.new "value is too big to be encrypted"
      end
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_encrypt(from.size, from, to, rsa, padding)
      if len < 0
        raise RsaError.new "unable to encrypt"
      end
      to[0, len]
    end

    def public_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_decrypt(from.size, from, to, rsa, padding)
      if len < 0
        raise RsaError.new "unable to decrypt"
      end
      to[0, len]
    end

    def private_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      unless private?
        raise RsaError.new "private key needed"
      end
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_encrypt(from.size, from, to, rsa, padding)
      if len < 0
        raise RsaError.new "unable to encrypt"
      end
      to[0, len]
    end

    def private_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      unless private?
        raise RsaError.new "private key needed"
      end

      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_decrypt(from.size, from, to, rsa, padding)
      if len < 0
        raise RsaError.new "unable to decrypt"
      end
      to[0, len]
    end

    def blinding_on?
      @blinding_on
    end

    def blinding_on!
      @blinding_on = (LibCrypto.rsa_blinding_on(rsa, nil) == 1)
    end

    def blinding_off!
      LibCrypto.rsa_blinding_off(rsa)
      @blinding_on = false
    end

    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
      # Sign data using RSA-PSS padding
      def sign_pss(digest : OpenSSL::Digest, data : String | Bytes) : Bytes
        unless private?
          raise RsaError.new "private key needed"
        end

        data_slice = data.to_slice
        digest_copy = digest.dup
        digest_copy.update(data_slice)
        hash = digest_copy.final

        ctx = LibCrypto.evp_pkey_ctx_new(self.to_unsafe, nil)
        raise RsaError.new "Could not create EVP_PKEY_CTX" if ctx.null?

        begin
          if LibCrypto.evp_pkey_sign_init(ctx) <= 0
            raise RsaError.new "Could not initialize signing"
          end

          if LibCrypto.evp_pkey_ctx_set_rsa_padding(ctx, LibCrypto::Padding::PKCS1_PSS_PADDING.value) <= 0
            raise RsaError.new "Could not set PSS padding"
          end

          if LibCrypto.evp_pkey_ctx_set_signature_md(ctx, digest.to_unsafe_md) <= 0
            raise RsaError.new "Could not set signature digest"
          end

          # Set salt length to match digest length (recommended)
          if LibCrypto.evp_pkey_ctx_set_rsa_pss_saltlen(ctx, -1) <= 0
            raise RsaError.new "Could not set PSS salt length"
          end

          sig_len = LibC::SizeT.new(0)
          if LibCrypto.evp_pkey_sign(ctx, nil, pointerof(sig_len), hash, hash.size) <= 0
            raise RsaError.new "Could not determine signature length"
          end

          signature = Bytes.new(sig_len)
          if LibCrypto.evp_pkey_sign(ctx, signature, pointerof(sig_len), hash, hash.size) <= 0
            raise RsaError.new "Could not sign data"
          end

          signature[0, sig_len]
        ensure
          LibCrypto.evp_pkey_ctx_free(ctx) unless ctx.null?
        end
      end

      # Verify signature using RSA-PSS padding
      def verify_pss(digest : OpenSSL::Digest, signature : Bytes, data : String | Bytes) : Bool
        data_slice = data.to_slice
        digest_copy = digest.dup
        digest_copy.update(data_slice)
        hash = digest_copy.final

        ctx = LibCrypto.evp_pkey_ctx_new(self.to_unsafe, nil)
        return false if ctx.null?

        begin
          return false if LibCrypto.evp_pkey_verify_init(ctx) <= 0
          return false if LibCrypto.evp_pkey_ctx_set_rsa_padding(ctx, LibCrypto::Padding::PKCS1_PSS_PADDING.value) <= 0
          return false if LibCrypto.evp_pkey_ctx_set_signature_md(ctx, digest.to_unsafe_md) <= 0
          return false if LibCrypto.evp_pkey_ctx_set_rsa_pss_saltlen(ctx, -1) <= 0

          result = LibCrypto.evp_pkey_verify(ctx, signature, signature.size, hash, hash.size)
          result == 1
        ensure
          LibCrypto.evp_pkey_ctx_free(ctx) unless ctx.null?
        end
      end
    {% end %}
  end
end
