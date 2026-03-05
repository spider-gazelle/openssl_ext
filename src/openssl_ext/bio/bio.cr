module OpenSSL
  class BioError < Error; end
end

class OpenSSL::GETS_BIO
  BIO_C_FILE_TELL = 133
  BIO_C_FILE_SEEK = 128

  private def self.io_for(bio : LibCrypto::Bio*) : IO
    {% if OpenSSL::BIO.has_method?(:ktls_recv?) %}
      Box(OpenSSL::BIO).unbox(LibCrypto.BIO_get_data(bio)).io
    {% else %}
      Box(IO).unbox(LibCrypto.BIO_get_data(bio))
    {% end %}
  end

  GETS_BIO = begin
    crystal_bio = OpenSSL::BIO::CRYSTAL_BIO

    ctrl = Proc(LibCrypto::Bio*, LibC::Int, LibC::Long, Void*, LibC::Long).new do |bio, cmd, _num, _ptr|
      io = io_for(bio)
      val = {% begin %}
              case cmd
              when LibCrypto::CTRL_FLUSH
                io.flush
                1
              when LibCrypto::CTRL_PUSH, LibCrypto::CTRL_POP, LibCrypto::CTRL_EOF
                0
              when BIO_C_FILE_TELL, BIO_C_FILE_SEEK
                0
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS) %}
                when LibCrypto::CTRL_SET_KTLS
                  0
              {% elsif LibCrypto.has_constant?(:CTRL_SET_KTLS_SEND) %}
                when LibCrypto::CTRL_SET_KTLS_SEND
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_GET_KTLS_SEND) && LibCrypto.has_constant?(:CTRL_GET_KTLS_RECV) %}
                when LibCrypto::CTRL_GET_KTLS_SEND, LibCrypto::CTRL_GET_KTLS_RECV
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS_TX_SEND_CTRL_MSG) && LibCrypto.has_constant?(:CTRL_CLEAR_KTLS_TX_CTRL_MSG) %}
                when LibCrypto::CTRL_SET_KTLS_TX_SEND_CTRL_MSG, LibCrypto::CTRL_CLEAR_KTLS_TX_CTRL_MSG
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE) %}
                when LibCrypto::CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE
                  0
              {% end %}
              else
                STDERR.puts "WARNING: Unsupported BIO ctrl call (#{cmd})"
                0
              end
            {% end %}
      LibCrypto::Long.new(val)
    end

    bgets = Proc(LibCrypto::Bio*, LibC::Char*, LibC::Int, LibC::Int).new do |bio, buffer, len|
      io = io_for(bio)
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

  @bridge_bio : OpenSSL::BIO? = nil
  @boxed_data : Void* = Pointer(Void).null

  def initialize(@io : IO)
    @bio = LibCrypto.BIO_new(GETS_BIO)
    raise BioError.new("BIO_new") if @bio.null?

    {% if OpenSSL::BIO.has_method?(:ktls_recv?) %}
      # Crystal's BIO read/write callbacks unbox OpenSSL::BIO from BIO data.
      # Keep a dedicated bridge object so those callbacks can access `#io` safely.
      bridge_bio = OpenSSL::BIO.new(io)
      @bridge_bio = bridge_bio

      # Keep a reference to this box because it lives in C-land.
      @boxed_data = Box(OpenSSL::BIO).box(bridge_bio)
      LibCrypto.BIO_set_data(@bio, @boxed_data)
    {% else %}
      @boxed_data = Box(IO).box(io)
      LibCrypto.BIO_set_data(@bio, @boxed_data)
    {% end %}
  end

  def finalize
    LibCrypto.bio_free_all(@bio)
    if bridge = @bridge_bio
      LibCrypto.bio_free_all(bridge.to_unsafe)
    end
  end

  getter io

  def to_unsafe
    @bio
  end
end
