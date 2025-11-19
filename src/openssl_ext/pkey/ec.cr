require "../bio/mem_bio"
require "./pkey"

module OpenSSL::PKey
  class EcError < PKeyError; end

  class EC < PKey
    # Ensure EC_GROUP is properly set on a loaded EC key
    # This fixes issues where the group becomes null after loading from PEM
    private def self.ensure_group(ec_key : LibCrypto::EC_KEY) : Nil
      group = LibCrypto.ec_key_get0_group(ec_key)

      # If group is null or invalid, try to reconstruct it
      if group.null?
        # Get the curve name from the key if available
        # For keys loaded from PEM, we need to reconstruct the group
        # Try common curves (P-256 is most common for VAPID)
        ["P-256", "P-384", "P-521", "secp256k1"].each do |curve_name|
          nid = LibCrypto.ec_curve_nist2nid(curve_name)
          next if nid.zero?

          # Try to set the group
          new_group = LibCrypto.ec_group_new_by_curve_name(nid)
          next if new_group.null?

          # Set the group on the key
          if LibCrypto.ec_key_set_group(ec_key, new_group) == 1
            # Group set successfully
            LibCrypto.ec_group_free(new_group)
            return
          end
          LibCrypto.ec_group_free(new_group)
        end
      end
    end

    def self.new(key : String)
      self.new(IO::Memory.new(key))
    end

    def self.new(io : IO)
      content = Bytes.new(io.size)
      io.read(content)

      priv = true

      bio = GETS_BIO.new(IO::Memory.new(content))
      ec_key = LibCrypto.pem_read_bio_ecprivatekey(bio, nil, nil, nil)
      io.rewind

      if ec_key.null?
        begin
          decoded = Base64.decode(content)
          buf = IO::Memory.new(decoded)

          bio = GETS_BIO.new(buf)
          ec_key = LibCrypto.d2i_ecprivatekey_bio(bio, nil)
        rescue Base64::Error
        end
      end

      if ec_key.null?
        bio = GETS_BIO.new(io)
        ec_key = LibCrypto.pem_read_bio_ec_pubkey(bio, nil, nil, nil)
        priv = false unless ec_key.null?
        io.rewind
      end

      if ec_key.null?
        raise EcError.new "Neither PUB or PRIV key"
      end

      # Ensure the EC_GROUP is properly set before wrapping in EVP_PKEY
      ensure_group(ec_key)

      pkey = new(priv)
      LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      pkey
    end

    def self.new(size : Int32)
      generate(size)
    end

    def self.generate(size : Int32)
      nist_name = "P-#{size}"
      nid = LibCrypto.ec_curve_nist2nid(nist_name)

      if nid.zero?
        raise EcError.new "Can not find your specific key size"
      end

      generate(nist_name)
    end

    def self.generate(type : String)
      nid = LibCrypto.ec_curve_nist2nid(type)
      raise EcError.new("unknown NIST Curve: #{type}") if nid.zero?
      ec_key = LibCrypto.ec_key_new_by_curve_name(nid)
      LibCrypto.ec_key_set_asn1_flag(ec_key, LibCrypto::OPENSSL_EC_NAMED_CURVE)
      if LibCrypto.ec_key_generate_key(ec_key) == 0
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new
      end

      new(true).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      end
    end

    # Generate EC key by curve name (supports non-NIST curves like secp256k1)
    def self.generate_by_curve_name(curve_name : String)
      nid = LibCrypto.obj_txt2nid(curve_name)
      raise EcError.new("unknown curve: #{curve_name}") if nid.zero?

      ec_key = LibCrypto.ec_key_new_by_curve_name(nid)
      raise EcError.new("failed to create EC key") if ec_key.null?

      LibCrypto.ec_key_set_asn1_flag(ec_key, LibCrypto::OPENSSL_EC_NAMED_CURVE)
      if LibCrypto.ec_key_generate_key(ec_key) == 0
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to generate EC key")
      end

      new(true).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      end
    end

    # Create EC key from raw private key bytes
    # For P-256, expects 32 bytes; for P-384, expects 48 bytes, etc.
    def self.from_private_bytes(bytes : Bytes, curve : String = "P-256")
      nid = LibCrypto.ec_curve_nist2nid(curve)
      raise EcError.new("unknown NIST curve: #{curve}") if nid.zero?

      ec_key = LibCrypto.ec_key_new_by_curve_name(nid)
      raise EcError.new("failed to create EC key") if ec_key.null?

      LibCrypto.ec_key_set_asn1_flag(ec_key, LibCrypto::OPENSSL_EC_NAMED_CURVE)

      # Convert bytes to BIGNUM
      priv_bn = LibCrypto.bn_from_bin(bytes.to_unsafe.as(LibC::Char*), bytes.size, nil)
      if priv_bn.null?
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to convert private key bytes to BIGNUM")
      end

      # Set the private key
      if LibCrypto.ec_key_set_private_key(ec_key, priv_bn) != 1
        LibCrypto.bn_free(priv_bn)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to set private key")
      end

      # Derive the public key from the private key
      group = LibCrypto.ec_key_get0_group(ec_key)
      pub_point = LibCrypto.ec_point_new(group)
      if pub_point.null?
        LibCrypto.bn_free(priv_bn)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to create public key point")
      end

      # Compute public key: pub = priv * G (where G is the generator)
      if LibCrypto.ec_point_mul(group, pub_point, priv_bn, nil, nil, nil) != 1
        LibCrypto.ec_point_free(pub_point)
        LibCrypto.bn_free(priv_bn)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to compute public key")
      end

      # Set the public key
      if LibCrypto.ec_key_set_public_key(ec_key, pub_point) != 1
        LibCrypto.ec_point_free(pub_point)
        LibCrypto.bn_free(priv_bn)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to set public key")
      end

      # Note: ec_key now owns the pub_point, don't free it
      LibCrypto.bn_free(priv_bn)

      new(true).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      end
    end

    # Create public key from raw bytes (uncompressed format: 0x04 + x + y)
    def self.from_public_bytes(bytes : Bytes, curve : String = "P-256")
      nid = LibCrypto.ec_curve_nist2nid(curve)
      raise EcError.new("unknown NIST curve: #{curve}") if nid.zero?

      ec_key = LibCrypto.ec_key_new_by_curve_name(nid)
      raise EcError.new("failed to create EC key") if ec_key.null?

      LibCrypto.ec_key_set_asn1_flag(ec_key, LibCrypto::OPENSSL_EC_NAMED_CURVE)

      group = LibCrypto.ec_key_get0_group(ec_key)
      pub_point = LibCrypto.ec_point_new(group)
      if pub_point.null?
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to create public key point")
      end

      # Convert bytes to EC_POINT
      if LibCrypto.ec_point_oct2point(group, pub_point, bytes.to_unsafe.as(LibC::Char*), bytes.size, nil) != 1
        LibCrypto.ec_point_free(pub_point)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to convert bytes to EC_POINT")
      end

      # Verify point is on curve
      if LibCrypto.ec_point_is_on_curve(group, pub_point, nil) != 1
        LibCrypto.ec_point_free(pub_point)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("public key point is not on curve")
      end

      # Set the public key
      if LibCrypto.ec_key_set_public_key(ec_key, pub_point) != 1
        LibCrypto.ec_point_free(pub_point)
        LibCrypto.ec_key_free(ec_key)
        raise EcError.new("failed to set public key")
      end

      # Note: ec_key now owns the pub_point, don't free it

      new(false).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      end
    end

    def public_key
      f1 = ->LibCrypto.i2d_ec_pubkey
      f2 = ->LibCrypto.d2i_ec_pubkey

      pub_ec = LibCrypto.asn1_dup(f1.pointer, f2.pointer, ec.as(Void*))
      EC.new(false).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, pub_ec.as Pointer(Void))
      end
    end

    def to_pem(io)
      bio = GETS_BIO.new(io)
      if private?
        LibCrypto.pem_write_bio_ecprivatekey(bio, ec, nil, nil, 0, nil, nil)
      else
        LibCrypto.pem_write_bio_ec_pubkey(bio, ec)
      end
    end

    def to_text
      bio = MemBIO.new
      LibCrypto.ecdsa_print(bio, ec, 0)
      bio.to_string
    end

    def to_der(io)
      fn = ->(buf : UInt8**) {
        if private?
          LibCrypto.i2d_ecprivatekey(ec, buf)
        else
          LibCrypto.i2d_ec_pubkey(ec, buf)
        end
      }
      len = fn.call(Pointer(Pointer(UInt8)).null)
      if len <= 0
        raise EcError.new "Could not output in DER format"
      end
      slice = Slice(UInt8).new(len)
      p = slice.to_unsafe
      len = fn.call(pointerof(p))

      output = slice[0, len]
      io.write(output)
    end

    def ec_sign(data)
      unless private?
        raise EcError.new "need a private key"
      end
      data = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      if LibCrypto.ecdsa_sign(0, data, data.size, to, out len, ec) != 1
        raise EcError.new
      end
      to[0, len]
    end

    def ec_verify(digest, signature)
      digest = digest.to_slice
      signature = signature.to_slice
      res = LibCrypto.ecdsa_verify(0, digest, digest.size, signature, signature.size, ec)

      case res
      when 1
        true
      when 0
        false
      else
        raise EcError.new
      end
    end

    # Export private key as raw bytes
    def private_key_bytes : Bytes
      raise EcError.new("not a private key") unless private?

      priv_bn = LibCrypto.ec_key_get0_private_key(ec)
      raise EcError.new("failed to get private key") if priv_bn.null?

      # Calculate the size needed: BN_num_bytes is a macro that does (BN_num_bits + 7) / 8
      num_bits = LibCrypto.bn_num_bits(priv_bn)
      raise EcError.new("failed to get private key bits") if num_bits <= 0
      size = (num_bits + 7) // 8

      # Allocate buffer and convert
      bytes = Bytes.new(size)
      result = LibCrypto.bn_to_bin(priv_bn, bytes.to_unsafe.as(LibC::Char*))
      raise EcError.new("failed to convert private key to bytes") if result != size

      bytes
    end

    # Export public key as raw bytes (uncompressed format: 0x04 + x + y)
    def public_key_bytes : Bytes
      pub_point = LibCrypto.ec_key_get0_public_key(ec)
      raise EcError.new("failed to get public key") if pub_point.null?

      group = LibCrypto.ec_key_get0_group(ec)

      # Get the size needed for uncompressed format
      size = LibCrypto.ec_point_point2oct(group, pub_point, LibCrypto::PointConversionForm::UNCOMPRESSED, Pointer(LibC::Char).null, 0, nil)
      raise EcError.new("failed to get public key size") if size == 0

      # Allocate buffer and convert
      bytes = Bytes.new(size)
      result_size = LibCrypto.ec_point_point2oct(group, pub_point, LibCrypto::PointConversionForm::UNCOMPRESSED, bytes.to_unsafe.as(LibC::Char*), size, nil)
      raise EcError.new("failed to convert public key to bytes") if result_size == 0

      bytes
    end

    def group
      EC::Group.new self
    end

    def group_degree
      LibCrypto.ec_group_get_degree LibCrypto.ec_key_get0_group(ec)
    end

    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
      # OpenSSL 3.x ECDH using EVP_PKEY_derive
      # Returns the raw ECDH shared secret (no KDF). Feed this into HKDF, etc.
      def self.compute_shared_secret(
        private_key : OpenSSL::PKey::EC,
        peer_public_key : OpenSSL::PKey::EC,
      ) : Bytes
        # Grab underlying EVP_PKEY* (openssl_ext/OpenSSL::PKey::* expose to_unsafe)
        priv_pkey = private_key.to_unsafe
        peer_pkey = peer_public_key.to_unsafe
        raise OpenSSL::Error.new("nil private EVP_PKEY") if priv_pkey.null?
        raise OpenSSL::Error.new("nil peer EVP_PKEY") if peer_pkey.null?

        # Create a derivation context bound to the private key
        ctx = LibCrypto.evp_pkey_ctx_new(priv_pkey, nil)
        raise OpenSSL::Error.new("EVP_PKEY_CTX_new failed") if ctx.null?

        begin
          # Initialize for derive
          rc = LibCrypto.evp_pkey_derive_init(ctx)
          raise OpenSSL::Error.new("EVP_PKEY_derive_init failed") unless rc == 1

          # Provide the peer public key
          rc = LibCrypto.evp_pkey_derive_set_peer(ctx, peer_pkey)
          raise OpenSSL::Error.new("EVP_PKEY_derive_set_peer failed (curve mismatch or invalid key)") unless rc == 1

          # Query output length
          out_len = LibC::SizeT.new(0)
          rc = LibCrypto.evp_pkey_derive(ctx, Pointer(UInt8).null, pointerof(out_len))
          raise OpenSSL::Error.new("EVP_PKEY_derive(size) failed") unless rc == 1
          raise OpenSSL::Error.new("unexpected zero length from derive") if out_len == 0

          # Derive into buffer
          secret = Bytes.new(out_len)
          rc = LibCrypto.evp_pkey_derive(ctx, secret.to_unsafe, pointerof(out_len))
          raise OpenSSL::Error.new("EVP_PKEY_derive failed") unless rc == 1

          # Trim in case provider wrote fewer bytes than estimated
          secret[0, out_len]
        ensure
          LibCrypto.evp_pkey_ctx_free(ctx)
        end
      end
    {% end %}

    private def ec
      LibCrypto.evp_pkey_get1_ec_key(self)
    end

    private def max_encrypt_size
      LibCrypto.ecdsa_size(ec)
    end
  end
end

require "./ec/*"
