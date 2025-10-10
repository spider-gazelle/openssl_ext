require "../lib_crypto"

class OpenSSL::ASN1::Time
  def initialize(@handle : LibCrypto::ASN1_TIME)
    raise OpenSSL::Error.new "Invalid handle" unless @handle
  end

  def initialize(period)
    initialize LibCrypto.x509_gmtime_adj(nil, period.to_i64)
  end

  def self.days_from_now(days)
    new(days * 60 * 60 * 24)
  end

  def finalize
    LibCrypto.asn1_time_free(self)
  end

  def to_unsafe
    @handle
  end

  # Convert ASN1_TIME to a string representation
  def to_s : String
    io = IO::Memory.new
    bio = OpenSSL::GETS_BIO.new(io)

    if LibCrypto.asn1_time_print(bio, @handle) == 0
      raise OpenSSL::Error.new("Failed to print ASN1_TIME")
    end

    io.to_s
  end

  # Convert ASN1_TIME to Crystal Time object
  def to_time : ::Time
    # ASN1_TIME_print outputs format like "Jan  1 00:00:00 2025 GMT"
    time_str = to_s

    # Parse the time string
    # Format: "MMM dd HH:mm:ss yyyy GMT" or "MMM  d HH:mm:ss yyyy GMT" (note single digit day with extra space)
    ::Time.parse(time_str, "%b %e %H:%M:%S %Y %Z", ::Time::Location::UTC)
  rescue ex : ::Time::Format::Error
    raise OpenSSL::Error.new("Failed to parse ASN1_TIME: #{ex.message}")
  end
end
