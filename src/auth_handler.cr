class OpenIDConnect::AuthHandler
  Log = ::Log.for("oidc.auth")

  include HTTP::Handler

  alias AfterAuthenticationCallback = (HTTP::Server::Context, OpenIDConnect::IDToken, OAuth2::AccessToken, OpenIDConnect::Provider) ->

  property! provider : OpenIDConnect::Provider

  property default_scope = "openid offline_access"

  property random = Random.new

  def self.new(provider : OpenIDConnect::Provider? = nil, *, default_redirect_url : String)
    new(provider) do |context|
      context.response.headers.add "Location", redirect_url
      context.response.status = HTTP::Status::FOUND
      context.response.close
    end
  end

  def self.new(provider : OpenIDConnect::Provider? = nil, &after_authentication : AfterAuthenticationCallback)
    new(provider, after_authentication)
  end

  def initialize(@provider : OpenIDConnect::Provider? = nil, @after_authentication : AfterAuthenticationCallback? = nil)
  end

  def redirect_path
    provider.redirect_uri.try do |uri|
      URI.parse(uri).path
    end
  end

  def authorize!(context : HTTP::Server::Context, scope : String = default_scope) : Nil
    nonce = random.urlsafe_base64
    state = random.urlsafe_base64

    yield state, nonce

    authorize!(context, scope, state, nonce)
  end

  def authorize!(context : HTTP::Server::Context, scope : String = default_scope, state : String? = nil, nonce : String? = nil) : Nil
    uri = provider.authorize_uri(scope, state: state, nonce: nonce)

    Log.debug { "Authorization redirect to #{uri}" }

    context.response.headers.add "Location", uri
    context.response.status = HTTP::Status::FOUND
    context.response.close
  end

  def call(context : HTTP::Server::Context)
    if context.request.path == redirect_path
      handle_redirect(context)
    else
      call_next(context)
    end
  end

  def handle_redirect(context : HTTP::Server::Context)
    if error = context.request.query_params["error"]?
      error_description = context.request.query_params["error_description"]?

      Log.warn { "Authorization redirect error: #{error} (#{error_description})" }

      handle_authorization_error(context, error, error_description)
    elsif authorization_code = context.request.query_params["code"]?
      handle_authorization_code(context, authorization_code)
    else
      raise "Missing code parameter"
    end
  end

  def handle_authorization_code(context : HTTP::Server::Context, authorization_code : String)
    state, nonce = get_state_and_nonce(context)

    if state
      case state_param = context.request.query_params["state"]?
      when Nil
        raise OAuth2::Error.new("Missing state parameter")
      when state_param
        # all good
      else
        raise OAuth2::Error.new("Invalid state parameter")
      end
    end

    Log.debug { "Received authorization code #{authorization_code}" }

    id_token, access_token = provider.get_id_token(authorization_code, nonce: nonce)

    Log.info(&.emit("Received id token", subject: id_token.subject, issuer: id_token.issuer))

    after_authentication(context, id_token, access_token)
  end

  def handle_authorization_error(context : HTTP::Server::Context, error, error_description)
    context.response.status = HTTP::Status::UNAUTHORIZED
    context.response.puts error
    if error_description
      context.response.puts error_description
    end
    context.response.close
  end

  def get_state_and_nonce(context : HTTP::Server::Context) : {String?, String?}
    {nil, nil}
  end

  def after_authentication(context, id_token, access_token)
    if after_authentication = @after_authentication
      after_authentication.call(context, id_token, access_token, provider)
    else
      call_next(context)
    end
  end

  def get_id_token(authorization_code, state_param, state, nonce)
    case state_param
    when Nil
      raise OAuth2::Error.new("Missing state parameter")
    when state
      # all good
    else
      raise OAuth2::Error.new("Invalid state parameter")
    end

    Log.debug { "Received authorization code #{authorization_code}" }

    id_token, access_token = provider.get_id_token(authorization_code, nonce: nonce)

    Log.info(&.emit("Received id token", subject: id_token.subject, issuer: id_token.issuer))

    {id_token, access_token}
  end
end
