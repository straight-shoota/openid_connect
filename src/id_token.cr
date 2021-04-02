require "json"
require "uri"

def URI.new(pull : JSON::PullParser)
  parse pull.read_string
end

module OpenIDConnect
  # Represents an OpenID ID token.
  record IDToken,
    issuer : String, subject : String, audience : Array(String),
    issued_at : Time = Time.utc.at_beginning_of_second, expires : Time = Time.utc.at_beginning_of_second + 5.minutes,
    auth_time : Time = Time.utc.at_beginning_of_second,
    nonce : String? = nil,
    authentication_context_class_reference : String? = nil, authentication_methods_references : Array(String)? = nil,
    authorized_party : String? = nil, access_token_hash : String? = nil

  struct IDToken
    # Raised when an ID token is invalid.
    class InvalidTokenError < Exception
      def initialize(message, @id_token : IDToken)
        super(message)
      end
    end

    # This is a JSON converter for serializing and deserializing an array of
    # values. Where a single scalar value is de serialized to an array including
    # only that value.
    module ArrayOrSingleConverter(T)
      def self.from_json(parser : JSON::PullParser)
        if parser.kind.begin_array?
          Array(T).new(parser)
        else
          [T.new(parser)]
        end
      end

      def self.to_json(value, json)
        value.to_json(json)
      end
    end

    include JSON::Serializable
    include JSON::Serializable::Unmapped

    @[JSON::Field(key: "iss")]
    @issuer : String

    @[JSON::Field(key: "sub")]
    @subject : String

    @[JSON::Field(key: "aud", converter: OpenIDConnect::IDToken::ArrayOrSingleConverter(String))]
    @audience : Array(String)

    @[JSON::Field(key: "exp", converter: Time::EpochConverter)]
    @expires : Time

    @[JSON::Field(key: "iat", converter: Time::EpochConverter)]
    @issued_at : Time

    @[JSON::Field(key: "auth_time", converter: Time::EpochConverter)]
    @auth_time : Time

    @[JSON::Field(key: "nonce")]
    @nonce : String?

    @[JSON::Field(key: "acr")]
    @authentication_context_class_reference : String?

    @[JSON::Field(key: "amr")]
    @authentication_methods_references : Array(String)?

    @[JSON::Field(key: "azp")]
    @authorized_party : String?

    @[JSON::Field(key: "at_hash")]
    @access_token_hash : String?

    # Returns `true` if *time* is after `expires`.
    def expired?(time = Time.utc)
      expires < time
    end

    # Validates this ID token and raises `InvalidTokenError` if invalid.
    #
    # See `validate` for details.
    def validate!(*, issuer : String? = nil, client_id : String? = nil, authorized_party : String? = client_id, nonce : String? = nil, time : Time = Time.utc) : Nil
      validate(issuer: issuer, nonce: nonce, client_id: client_id, authorized_party: authorized_party, time: time).try do |error|
        raise error
      end
    end

    # Returns `true` if this ID token is valid.
    #
    # See `validate` for details.
    def valid?(*, issuer : String? = nil, client_id : String? = nil, authorized_party : String? = client_id, nonce : String? = nil, time : Time = Time.utc) : Bool
      validate(issuer: issuer, nonce: nonce, client_id: client_id, authorized_party: authorized_party, time: time).nil?
    end

    # Validates this ID token and returns `InvalidTokenError` if invalid.
    #
    # Validation steps:
    # * Checks expiration time against *time*.
    # * If *issuer* is given, makes sure it's equal to `issuer`.
    # * If *client_id*  is given, makes sure `audience` includes it.
    # * Makes sure `nonce` is equal to *nonce*.
    # * If *authorized_party*  is given (defaults to *client_id*), makes sure
    #   it's equal to `authorized_party`.
    def validate(*, issuer : String? = nil, client_id : String? = nil, authorized_party : String? = client_id, nonce : String? = nil, time : Time = Time.utc) : InvalidTokenError?
      if expired?(time)
        return InvalidTokenError.new("Invalid ID token: Expired token", self)
      end

      if issuer && issuer != self.issuer
        return InvalidTokenError.new("Invalid ID token: Issuer does not match", self)
      end

      if nonce && self.nonce != nonce
        return InvalidTokenError.new("Invalid ID token: Nonce does not match", self)
      end

      if client_id && !audience.includes?(client_id)
        return InvalidTokenError.new("Invalid ID token: Audience does not match", self)
      end

      if authorized_party && (self.authorized_party != authorized_party)
        return InvalidTokenError.new("Invalid ID token: Authorized party does not match", self)
      end

      nil
    end
  end
end
