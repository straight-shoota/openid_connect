module OpenIDConnect
  record Session, id_token : IDToken, access_token : OAuth2::AccessToken

  class SessionHandler < AuthHandler
    # :nodoc:
    record AuthSession, redirect_uri : String, state : String, nonce : String

    def self.new(sessions : HTTPSession::Manager(Session))
      storage = HTTPSession::Storage::Memory(AuthSession).new
      auth_sessions = HTTPSession::Manager.new(storage)
      new(sessions, auth_sessions)
    end

    def initialize(@sessions : HTTPSession::Manager(Session), @auth_sessions : HTTPSession::Manager(AuthSession))
    end

    def authorize!(context : HTTP::Server::Context)
      authorize!(context) do |state, nonce|
        @auth_sessions.put(context, AuthSession.new(context.request.path, state, nonce))
      end
    end

    def handle_authorization_code(context : HTTP::Server::Context, authorization_code : String)
      unless auth_session = @auth_sessions.get(context, AuthSession)
        context.respond_with_status :bad_request
        return
      end

      id_token, access_token = get_id_token(context.request.query_params["state"]?, auth_session.state, auth_session.nonce)

      @sessions.put(context, Session.new(id_token, access_token))
      @auth_sessions.delete(context, auth_session)

      context.response.headers.add "Location", auth_session.redirect_uri
      context.response.status = HTTP::Status::FOUND
      context.response.close
    end
  end
end
