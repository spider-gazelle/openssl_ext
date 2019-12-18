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

      bio = GETS_BIO.new(io)
      rsa_key = LibCrypto.pem_read_bio_rsa_private_key(bio, nil, nil, passphrase)
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
        rsa_key = LibCrypto.pem_read_bio_rsa_public_key(bio, nil, nil, passphrase)
        priv = false unless rsa_key.null?
        io.rewind
      end

      if rsa_key.null?
        bio = GETS_BIO.new(io)
        rsa_key = LibCrypto.pem_read_bio_rsa_pubkey(bio, nil, nil, passphrase)
        priv = false unless rsa_key.null?
        io.rewind
      end

      raise RsaError.new("Neither PUB or PRIV key") if rsa_key.null?

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
      raise RsaError.new("Could not get public key from RSA") unless pub_rsa

      RSA.new(false).tap do |pkey|
        LibCrypto.evp_pkey_set1_rsa(pkey, pub_rsa)
      end
    end

    def public_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      raise RsaError.new("value is too big to be encrypted") if max_encrypt_size < from.size

      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_encrypt(from.size, from, to, rsa, padding)
      raise RsaError.new("unable to encrypt") if len < 0

      to[0, len]
    end

    def public_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_decrypt(from.size, from, to, rsa, padding)
      raise RsaError.new("unable to decrypt") if len < 0

      to[0, len]
    end

    def private_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      raise RsaError.new("private key needed") unless private?

      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_encrypt(from.size, from, to, rsa, padding)
      raise RsaError.new("unable to encrypt") if len < 0
      to[0, len]
    end

    def private_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      raise RsaError.new("private key needed") unless private?

      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_decrypt(from.size, from, to, rsa, padding)
      raise RsaError.new("unable to decrypt") if len < 0
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

    enum SaltTypePSS
      MAX = -2
      DIGEST = -1
    end

    # https://ruby-doc.org/stdlib-2.5.0/libdoc/openssl/rdoc/OpenSSL/PKey/RSA.html#method-i-sign_pss
    # https://www.openssl.org/docs/man1.1.0/man3/EVP_DigestSignInit.html
    # https://github.com/crystal-lang/crystal/blob/master/src/openssl/lib_crypto.cr
    # Note:: salt_length can be an integer
    def sign_pss(digest_algorithm, data, salt_length : SaltTypePSS | Int = SaltTypePSS::DIGEST, mgf1_hash = "sha256")
      raise RsaError.new("need a private key") unless private?

      salt_len = salt_length.to_i

      # Same as: https://github.com/crystal-lang/crystal/blob/939a81b06b68a0cb9e3e59a2a44e5c495668bd48/src/openssl/digest/digest.cr#L19
      md = LibCrypto.evp_get_digestbyname(digest_algorithm)
      raise RsaError.new("Unsupported digest algorithm: #{digest_algorithm}") unless md
      md_ctx = LibCrypto.evp_md_ctx_new
      raise RsaError.new "Digest initialization failed." unless md_ctx

      begin
        pkey_ctx = LibCrypto.evp_pkey_ctx_new(self, @pkey.value.engine)
        raise RsaError.new "Private key contex initialization failed." unless pkey_ctx

        begin
          result = LibCrypto.evp_digest_sign_init(md_ctx, pointerof(pkey_ctx), md, nil, self)
          raise RsaError.new "Digest sign initialization failed." if result != 1

          result = LibCrypto.set_rsa_padding(md_ctx, LibCrypto::RSA_PKCS1_PSS_PADDING)
          raise RsaError.new "RSA padding set failed." if result != 1
        ensure
          # LibCrypto.evp_pkey_ctx_free(pkey_ctx)
        end
      ensure
        LibCrypto.evp_md_ctx_free(md_ctx)
      end

  
    end
  end
end
