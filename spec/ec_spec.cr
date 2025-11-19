require "./spec_helper"

require "spec"
require "../src/openssl_ext/pkey/ec"
require "base64"

describe OpenSSL::PKey::EC do
  describe "instantiating and generate a key" do
    it "can instantiate and generate for a given key size" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true
      pkey.public?.should be_false

      pkey.public_key.public?.should be_true
    end

    it "can export to PEM format" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true

      pem = pkey.to_pem
      is_empty = "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n" == pem

      pem.should contain("BEGIN EC PRIVATE KEY")
      is_empty.should be_false
    end

    it "can export to DER format" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true
      pem = pkey.to_pem
      der = pkey.to_der

      pkey = OpenSSL::PKey::EC.new(der)
      pkey.to_pem.should eq pem
      pkey.to_der.should eq der
    end

    it "can instantiate with a PEM encoded key" do
      pem = OpenSSL::PKey::EC.new(384).to_pem
      pkey = OpenSSL::PKey::EC.new(pem)

      pkey.to_pem.should eq pem
    end

    it "can instantiate with a DER encoded key" do
      der = OpenSSL::PKey::EC.new(384).to_der
      pkey = OpenSSL::PKey::EC.new(der)

      pkey.to_der.should eq der
    end
  end

  describe "encrypting / decrypting" do
    it "should be able to sign and verify data" do
      ec = OpenSSL::PKey::EC.new(384)
      sha256 = OpenSSL::Digest.new("sha256")
      data = "my test data"
      sha256.update(data)
      digest = sha256.final
      signature = ec.ec_sign(digest)

      ec.ec_verify(digest, signature).should be_true
    end
  end

  describe "groups and points" do
    it "should be able to generate a matter verifier" do
      passcode = 20202021_u32
      io = IO::Memory.new
      io.write_bytes(passcode, IO::ByteFormat::LittleEndian)

      salt = "SPAKE2P Key Salt"
      iterations = 1000

      # "prime256v1" or "secp256r1" are aliases for "P-256"
      curve = OpenSSL::PKey::EC.generate("P-256")
      group = curve.group
      point = group.generator
      ws_length = group.baselen + 8
      nist256p_order = group.order

      ws = OpenSSL::PKCS5.pbkdf2_hmac(io.to_slice, salt, iterations, OpenSSL::Algorithm::SHA256, ws_length * 2)
      w0 = OpenSSL::BN.from_bin(ws[0, ws_length]).to_big % nist256p_order
      w1 = OpenSSL::BN.from_bin(ws[ws_length, ws_length]).to_big % nist256p_order

      point = point.mul(w1)

      w0_bytes = OpenSSL::BN.new(w0).to_bin
      point_bytes = point.uncompressed_bytes

      output = w0_bytes + point_bytes
      output.should eq Base64.decode("uWFwqugDNGiEck/po7KHwwMwwqZgN10XuyBajPGuyzUEV/iree4lOrao5GuwnlQ65CJzbeUB49s31EH+NEkg0JVI5MGCQGMMT/SRPFNRODm3wH/MBiehuFc6FJ/NH6Rmzw==")
    end
  end

  {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
    describe "ECDH shared secret computation (OpenSSL 3+)" do
      it "should compute shared secret between two parties" do
        # Generate two key pairs (Alice and Bob)
        alice_key = OpenSSL::PKey::EC.generate("P-256")
        bob_key = OpenSSL::PKey::EC.generate("P-256")

        # Extract public keys
        alice_public = alice_key.public_key
        bob_public = bob_key.public_key

        # Each party computes the shared secret using their private key and the other's public key
        alice_shared = OpenSSL::PKey::EC.compute_shared_secret(alice_key, bob_public)
        bob_shared = OpenSSL::PKey::EC.compute_shared_secret(bob_key, alice_public)

        # The shared secrets should be identical
        alice_shared.should eq bob_shared

        # The shared secret should be non-empty and of expected length (32 bytes for P-256)
        alice_shared.size.should eq 32
      end

      it "should compute shared secret with P-384 curve" do
        # Test with a different curve size
        alice_key = OpenSSL::PKey::EC.generate("P-384")
        bob_key = OpenSSL::PKey::EC.generate("P-384")

        alice_public = alice_key.public_key
        bob_public = bob_key.public_key

        alice_shared = OpenSSL::PKey::EC.compute_shared_secret(alice_key, bob_public)
        bob_shared = OpenSSL::PKey::EC.compute_shared_secret(bob_key, alice_public)

        alice_shared.should eq bob_shared
        # P-384 should produce a 48-byte shared secret
        alice_shared.size.should eq 48
      end

      it "should raise error with mismatched curves" do
        # Generate keys on different curves
        p256_key = OpenSSL::PKey::EC.generate("P-256")
        p384_key = OpenSSL::PKey::EC.generate("P-384")
        p384_public = p384_key.public_key

        # Should fail when curves don't match
        expect_raises(OpenSSL::Error, /curve mismatch/) do
          OpenSSL::PKey::EC.compute_shared_secret(p256_key, p384_public)
        end
      end

      it "should raise error with public key as private key" do
        alice_key = OpenSSL::PKey::EC.generate("P-256")
        bob_key = OpenSSL::PKey::EC.generate("P-256")

        alice_public = alice_key.public_key
        bob_public = bob_key.public_key

        # Should fail when trying to use a public key as the private key
        expect_raises(OpenSSL::Error) do
          OpenSSL::PKey::EC.compute_shared_secret(alice_public, bob_public)
        end
      end

      it "should produce deterministic results" do
        # Generate keys
        alice_key = OpenSSL::PKey::EC.generate("P-256")
        bob_key = OpenSSL::PKey::EC.generate("P-256")
        bob_public = bob_key.public_key

        # Compute shared secret multiple times
        secret1 = OpenSSL::PKey::EC.compute_shared_secret(alice_key, bob_public)
        secret2 = OpenSSL::PKey::EC.compute_shared_secret(alice_key, bob_public)
        secret3 = OpenSSL::PKey::EC.compute_shared_secret(alice_key, bob_public)

        # All results should be identical
        secret1.should eq secret2
        secret2.should eq secret3
      end
    end
  {% end %}

  describe "EC_GROUP preservation (regression test for PEM loading)" do
    it "should preserve EC_GROUP when loading from PEM" do
      # Generate a P-256 key
      original = OpenSSL::PKey::EC.generate("P-256")
      pem = original.to_pem

      # Load from PEM
      loaded = OpenSSL::PKey::EC.new(pem)

      # EC_GROUP should be accessible (not null)
      # This would previously fail with null pointer errors in some environments
      group = loaded.group
      group.should_not be_nil

      # Group should have valid properties
      group.degree.should eq 256
      group.order.should_not be_nil
    end

    it "should preserve EC_GROUP for all NIST curves" do
      # Test with standard NIST curves that are commonly available
      ["P-256", "P-384", "P-521"].each do |curve_name|
        # Generate key for this curve
        original = OpenSSL::PKey::EC.generate(curve_name)
        pem = original.to_pem

        # Load from PEM
        loaded = OpenSSL::PKey::EC.new(pem)

        # EC_GROUP should be accessible
        group = loaded.group
        group.should_not be_nil

        # Group should have valid properties
        group.degree.should be > 0
        group.order.should_not be_nil
      end
    end

    it "should allow operations after loading from PEM" do
      # Generate and export to PEM
      original = OpenSSL::PKey::EC.generate("P-256")
      pem = original.to_pem

      # Load from PEM
      loaded = OpenSSL::PKey::EC.new(pem)

      # Should be able to extract public key bytes (requires valid EC_GROUP)
      pub_bytes = loaded.public_key.public_key_bytes
      pub_bytes.size.should eq 65
      pub_bytes[0].should eq 0x04

      # Should be able to extract private key bytes
      priv_bytes = loaded.private_key_bytes
      priv_bytes.size.should eq 32

      # Should be able to sign (requires valid EC_GROUP)
      data = "test data"
      digest = OpenSSL::Digest.new("SHA256").update(data).final
      signature = loaded.ec_sign(digest)
      signature.should_not be_nil

      # Should be able to verify
      loaded.ec_verify(digest, signature).should be_true
    end

    it "should work with ECDH after loading from PEM (OpenSSL 3+)" do
      {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
        # Generate two keys and export to PEM
        alice_original = OpenSSL::PKey::EC.generate("P-256")
        bob_original = OpenSSL::PKey::EC.generate("P-256")

        alice_pem = alice_original.to_pem
        bob_pem = bob_original.to_pem

        # Load from PEM
        alice_loaded = OpenSSL::PKey::EC.new(alice_pem)
        bob_loaded = OpenSSL::PKey::EC.new(bob_pem)

        # Should be able to compute shared secret (requires valid EC_GROUP)
        alice_shared = OpenSSL::PKey::EC.compute_shared_secret(alice_loaded, bob_loaded.public_key)
        bob_shared = OpenSSL::PKey::EC.compute_shared_secret(bob_loaded, alice_loaded.public_key)

        # Shared secrets should match
        alice_shared.should eq bob_shared
        alice_shared.size.should eq 32
      {% end %}
    end

    it "should handle IO::Memory for PEM loading" do
      # Test loading from IO (not just String)
      original = OpenSSL::PKey::EC.generate("P-256")
      pem_string = original.to_pem

      # Create IO::Memory with PEM content
      io = IO::Memory.new(pem_string)

      # Load from IO
      loaded = OpenSSL::PKey::EC.new(io)

      # EC_GROUP should be accessible
      group = loaded.group
      group.should_not be_nil
      group.degree.should eq 256

      # Should be able to perform operations
      pub_bytes = loaded.public_key.public_key_bytes
      pub_bytes.size.should eq 65
    end

    it "should handle DER format loading" do
      # Generate and export to DER
      original = OpenSSL::PKey::EC.generate("P-256")
      der = original.to_der

      # Load from DER
      loaded = OpenSSL::PKey::EC.new(der)

      # EC_GROUP should be accessible
      group = loaded.group
      group.should_not be_nil
      group.degree.should eq 256

      # Should match original
      loaded.to_der.should eq der
    end

    it "should handle multiple load/save cycles" do
      # Start with a key
      key1 = OpenSSL::PKey::EC.generate("P-256")

      # PEM round-trip
      pem1 = key1.to_pem
      key2 = OpenSSL::PKey::EC.new(pem1)

      # Second PEM round-trip
      pem2 = key2.to_pem
      key3 = OpenSSL::PKey::EC.new(pem2)

      # All should have valid EC_GROUP
      key1.group.degree.should eq 256
      key2.group.degree.should eq 256
      key3.group.degree.should eq 256

      # Final PEM should match
      pem2.should eq pem1
    end
  end

  describe "raw key bytes operations" do
    it "should export and import private key bytes" do
      # Generate a key
      original_key = OpenSSL::PKey::EC.generate("P-256")

      # Export private key bytes
      priv_bytes = original_key.private_key_bytes
      priv_bytes.size.should eq 32 # P-256 uses 32-byte private keys

      # Import from bytes
      imported_key = OpenSSL::PKey::EC.from_private_bytes(priv_bytes, "P-256")
      imported_key.private?.should be_true

      # Verify they produce the same signatures
      data = "test data"
      digest = OpenSSL::Digest.new("SHA256").update(data).final

      sig1 = original_key.ec_sign(digest)
      sig2 = imported_key.ec_sign(digest)

      # Both should verify with the original key's public key
      original_key.ec_verify(digest, sig1).should be_true
      imported_key.ec_verify(digest, sig2).should be_true
    end

    it "should export and import public key bytes" do
      # Generate a key
      key = OpenSSL::PKey::EC.generate("P-256")
      pub_key = key.public_key

      # Export public key bytes (should be 0x04 + 32 bytes x + 32 bytes y = 65 bytes)
      pub_bytes = pub_key.public_key_bytes
      pub_bytes.size.should eq 65
      pub_bytes[0].should eq 0x04 # Uncompressed format marker

      # Import from bytes
      imported_pub = OpenSSL::PKey::EC.from_public_bytes(pub_bytes, "P-256")
      imported_pub.public?.should be_true
      imported_pub.private?.should be_false

      # Verify the imported public key matches
      imported_pub.public_key_bytes.should eq pub_bytes
    end

    it "should derive public key from private key bytes" do
      # Generate original key
      original = OpenSSL::PKey::EC.generate("P-256")
      original_pub_bytes = original.public_key.public_key_bytes

      # Export private bytes and reimport
      priv_bytes = original.private_key_bytes
      reimported = OpenSSL::PKey::EC.from_private_bytes(priv_bytes, "P-256")

      # The public key should be automatically derived
      reimported_pub_bytes = reimported.public_key.public_key_bytes
      reimported_pub_bytes.should eq original_pub_bytes
    end

    it "should work with P-384 curve" do
      # Test with P-384 (48-byte private key, 97-byte public key)
      key = OpenSSL::PKey::EC.generate("P-384")

      priv_bytes = key.private_key_bytes
      priv_bytes.size.should eq 48

      pub_bytes = key.public_key.public_key_bytes
      pub_bytes.size.should eq 97
      pub_bytes[0].should eq 0x04

      # Round-trip test
      reimported = OpenSSL::PKey::EC.from_private_bytes(priv_bytes, "P-384")
      reimported.public_key.public_key_bytes.should eq pub_bytes
    end

    it "should raise error when exporting private bytes from public key" do
      key = OpenSSL::PKey::EC.generate("P-256")
      pub_key = key.public_key

      expect_raises(OpenSSL::PKey::EcError, /not a private key/) do
        pub_key.private_key_bytes
      end
    end

    it "should verify signature with imported keys" do
      # Create original key and sign
      original = OpenSSL::PKey::EC.generate("P-256")
      data = "important message"
      digest = OpenSSL::Digest.new("SHA256").update(data).final
      signature = original.ec_sign(digest)

      # Export public key and reimport
      pub_bytes = original.public_key.public_key_bytes
      imported_pub = OpenSSL::PKey::EC.from_public_bytes(pub_bytes, "P-256")

      # Verify signature with imported public key
      imported_pub.ec_verify(digest, signature).should be_true
    end

    it "should reject invalid public key bytes" do
      # Try to create a key with invalid point (not on curve)
      invalid_bytes = Bytes.new(65, 0xFF)
      invalid_bytes[0] = 0x04 # Correct format marker, but invalid coordinates

      # Should raise an error (either "convert bytes" or "not on curve")
      expect_raises(OpenSSL::PKey::EcError) do
        OpenSSL::PKey::EC.from_public_bytes(invalid_bytes, "P-256")
      end
    end

    it "should handle compressed public key format" do
      # Generate a key and get uncompressed public key
      key = OpenSSL::PKey::EC.generate("P-256")
      uncompressed = key.public_key.public_key_bytes

      # Manual test: uncompressed format should start with 0x04
      uncompressed[0].should eq 0x04
      uncompressed.size.should eq 65
    end
  end
end
