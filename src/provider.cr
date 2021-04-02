require "oauth2"
require "jwt"
require "./id_token"

class OAuth2::Client
  getter client_id : String
  getter client_secret : String
  getter redirect_uri : String?
end

# Configuration for an OpenID Provider.
class OpenIDConnect::Provider
  Log = ::Log.for("oidc.provider")

  # Returns the issuer URI.
  getter issuer : URI

  # Returns the public key which is used for validating tokens.
  getter public_key : String?

  # Returns the `OAuth2::Client` used as a basis.
  getter client : OAuth2::Client

  # Returns the userinfo endpoint for the provider.
  getter userinfo_endpoint : URI?

  def_equals_and_hash issuer, public_key, client, userinfo_endpoint

  # Creates a new instance.
  #
  # A new `OAuth2::Client` instance is created from the given information based
  # on *issuer*.
  #
  # If *issuer* is a string, it's assumed to be a domain name and parsed as a
  # `URI`.
  def self.new(issuer : URI | String, *,
               client_id : String, client_secret : String,
               authorize_endpoint = "/oauth2/authorize",
               token_endpoint = "/oauth2/token",
               userinfo_endpoint : URI | String? = nil,
               redirect_uri : String? = nil,
               public_key : String? = nil)
    if issuer.is_a?(String)
      if issuer.starts_with?("https://")
        issuer = URI.parse(issuer)
      else
        issuer = URI.parse("https://#{issuer}")
      end
    end

    host = issuer.host || raise ArgumentError.new("Invalid issuer URI")
    scheme = issuer.scheme || raise(ArgumentError.new("Invalid issuer URI"))

    oauth = OAuth2::Client.new(
      host,
      client_id: client_id, client_secret: client_secret,
      port: issuer.port,
      scheme: scheme,
      authorize_uri: authorize_endpoint, token_uri: token_endpoint,
      redirect_uri: redirect_uri
    )
    if userinfo_endpoint.is_a?(String)
      userinfo_endpoint = URI.parse(userinfo_endpoint)
    end

    new(issuer, oauth,
      public_key: public_key,
      userinfo_endpoint: userinfo_endpoint)
  end

  # Creates a new instance.
  def initialize(@issuer : URI, @client : OAuth2::Client, @public_key : String? = nil, @userinfo_endpoint : URI? = nil)
  end

  def client_id
    client.client_id
  end

  def client_secret
    client.client_secret
  end

  def redirect_uri
    client.redirect_uri
  end

  # Returns an authorization URL for the given scope.
  #
  # *scope* can contain multiple scopes separated by whitespace and is expected
  # to include `openid`.
  def authorize_uri(scope : String = "openid", state : String? = nil, nonce : String? = nil) : String
    authorize_uri(scope, state, nonce) { }
  end

  # Returns an authorization URL for the given scope.
  #
  # *scope* can contain multiple scopes, separated by whitespace and is expected
  # to include `openid`.
  #
  # Yields `URI::Params::Bulider` for customization of query parameters.
  def authorize_uri(scope : String = "openid", state : String? = nil, nonce : String? = nil, & : URI::Params::Builder -> _) : String
    @client.get_authorize_uri(scope, state) do |form|
      if nonce
        form.add "nonce", nonce
      end

      yield form
    end
  end

  # Queries an ID token from the provider for *authorization_code*.
  #
  # The actual HTTP request is delegated to `client`.
  #
  # Raises `OAuth2::Error` if getting the token fails.
  def get_id_token?(authorization_code : String) : {IDToken, OAuth2::AccessToken}
    access_token = @client.get_access_token_using_authorization_code(authorization_code)

    id_token = access_token.extra.try(&.["id_token"]?)

    unless id_token
      raise OAuth2::Error.new("Invalid response: Missing id_token")
    end

    payload, header = decode_jwt(String.from_json(id_token))

    id_token = IDToken.from_json(payload.to_json)

    {id_token, access_token}
  end

  # Queries and validates an ID token from the provider for *authorization_code*.
  #
  # The actual HTTP request is delegated to `client`.
  #
  # Raises `OAuth2::Error` if getting the token fails.
  # Raises `IDToken::InvalidTokenError` if the received token is invalid.
  def get_id_token(authorization_code : String, nonce : String? = nil) : {IDToken, OAuth2::AccessToken}
    id_token, access_token = get_id_token?(authorization_code)
    id_token.validate!(issuer: issuer.to_s, client_id: client_id, nonce: nonce)

    {id_token, access_token}
  end

  # Decodes a JSON Web Token.
  #
  # If `public_key` is set, it is used to validate and verify the token.
  # Otherwise it's decoded unverified.
  def decode_jwt(token)
    if public_key = @public_key
      JWT.decode(token, public_key, JWT::Algorithm::RS256)
    else
      JWT.decode(token, verify: false, validate: false)
    end
  end

  # Queries the `userinfo_endpoint` to retrieve claims associated with the
  # subject identified by *id_token*.
  #
  # Yields the `HTTP::Response` for processing and returns the return value of
  # the block.
  #
  # NOTE: According to OpenID Connect specification, the Relying Party must
  # validate the `sub` claim to match the exact `sub` claim in the ID token.
  # This needs to be implemented in the given block.
  def get_userinfo(id_token : IDToken, access_token : OAuth2::AccessToken, & : HTTP::Client::Response -> T) : T forall T
    userinfo_endpoint = self.userinfo_endpoint
    raise "missing userinfo endpoint" unless userinfo_endpoint

    headers = HTTP::Headers{
      "Accept"       => "application/json",
      "Content-Type" => "application/x-www-form-urlencoded",
    }

    request = HTTP::Request.new("GET", userinfo_endpoint.request_target, headers: headers)
    access_token.authenticate(request, userinfo_endpoint.scheme == "https")

    response = client.http_client.exec(request)
    case response.status
    when .ok?, .created?
      yield response
    else
      raise OAuth2::Error.new(response.body)
    end
  end

  # Queries the `userinfo_endpoint` to retrieve claims associated with the
  # subject identified by *id_token*.
  #
  # Returns a `JSON::Any` representing the userinfo response.
  #
  # Validates the `sub` claim of the response to match the `sub` claim of the
  # *id_token*.
  def get_userinfo(id_token : IDToken, access_token : OAuth2::AccessToken) : JSON::Any
    get_userinfo(id_token, access_token) do |response|
      userinfo = JSON.parse(response.body)
      if subject = userinfo.as_h?.try(&.["sub"]?)
        if subject == id_token.subject
          userinfo
        else
          raise OAuth2::Error.new("Mismatched subject identifier in userinfo response.")
        end
      else
        raise OAuth2::Error.new("Missing subject identifier in userinfo response.")
      end
    end
  end
end

# TODO: Remove stdlib-override
class OAuth2::Client
  # Sets the `HTTP::Client` to use with this client.
  setter http_client : HTTP::Client?

  # Returns the `HTTP::Client` to use with this client.
  #
  # By default, this returns a new instance every time. To reuse the same instance,
  # one can be assigned with `#http_client=`.
  def http_client : HTTP::Client
    @http_client || HTTP::Client.new(token_uri)
  end

  private def get_access_token : AccessToken
    headers = HTTP::Headers{
      "Accept"       => "application/json",
      "Content-Type" => "application/x-www-form-urlencoded",
    }

    body = URI::Params.build do |form|
      case @auth_scheme
      when .request_body?
        form.add("client_id", @client_id)
        form.add("client_secret", @client_secret)
      when .http_basic?
        headers.add(
          "Authorization",
          "Basic #{Base64.strict_encode("#{@client_id}:#{@client_secret}")}"
        )
      end
      yield form
    end

    response = http_client.post token_uri.request_target, form: body, headers: headers
    case response.status
    when .ok?, .created?
      OAuth2::AccessToken.from_json(response.body)
    else
      raise OAuth2::Error.new(response.body)
    end
  end
end
