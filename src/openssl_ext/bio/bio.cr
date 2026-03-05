module OpenSSL
  class BioError < Error; end
end

class OpenSSL::GETS_BIO
  BIO_C_FILE_TELL = 133
  BIO_C_FILE_SEEK = 128

  GETS_BIO = begin
    crystal_bio = OpenSSL::BIO::CRYSTAL_BIO

    ctrl = Proc(LibCrypto::Bio*, LibC::Int, LibC::Long, Void*, LibC::Long).new do |bio, cmd, _num, _ptr|
      bio_obj = Box(OpenSSL::BIO).unbox(LibCrypto.BIO_get_data(bio))
      val = case cmd
            when LibCrypto::CTRL_FLUSH
              io = bio_obj.io
              io.flush
              1
            when LibCrypto::CTRL_PUSH, LibCrypto::CTRL_POP, LibCrypto::CTRL_EOF
              0
            when BIO_C_FILE_TELL, BIO_C_FILE_SEEK
              0
            when LibCrypto::CTRL_SET_KTLS
              0
            when LibCrypto::CTRL_GET_KTLS_SEND, LibCrypto::CTRL_GET_KTLS_RECV
              0
            else
              STDERR.puts "WARNING: Unsupported BIO ctrl call (#{cmd})"
              0
            end
      LibCrypto::Long.new(val)
    end

    bgets = Proc(LibCrypto::Bio*, LibC::Char*, LibC::Int, LibC::Int).new do |bio, buffer, len|
      bio_obj = Box(OpenSSL::BIO).unbox(LibCrypto.BIO_get_data(bio))
      io = bio_obj.io
      io.flush

      position = io.pos

      line = io.gets(len, false)

      if line.nil?
        0
      else
        io.seek(position)
        bytes = io.read(Slice.new(buffer, line.bytesize)).to_i

        bytes -= 1 unless bytes == 1
        bytes
      end
    end
    # use our version of ctrl to avoid warnings
    # is also more performant than the standard library version
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      LibCrypto.BIO_meth_set_ctrl(crystal_bio, ctrl)
      LibCrypto.BIO_meth_set_gets(crystal_bio, bgets)
    {% else %}
      crystal_bio.value.ctrl = ctrl
      crystal_bio.value.bgets = bgets
    {% end %}
    crystal_bio
  end

  @bridge_bio : OpenSSL::BIO
  @boxed_bio : Void*

  def initialize(@io : IO)
    @bio = LibCrypto.BIO_new(GETS_BIO)
    raise BioError.new("BIO_new") if @bio.null?

    # Crystal's BIO read/write callbacks unbox OpenSSL::BIO from BIO data.
    # Keep a dedicated bridge object so those callbacks can access `#io` safely.
    @bridge_bio = OpenSSL::BIO.new(io)

    # Keep a reference to this box because it lives in C-land.
    @boxed_bio = Box(OpenSSL::BIO).box(@bridge_bio)

    LibCrypto.BIO_set_data(@bio, @boxed_bio)
  end

  def finalize
    LibCrypto.bio_free_all(@bio)
    LibCrypto.bio_free_all(@bridge_bio.to_unsafe)
  end

  getter io

  def to_unsafe
    @bio
  end
end
