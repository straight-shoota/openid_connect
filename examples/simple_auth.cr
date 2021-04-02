require "../src/openid_connect"
require "../src/auth_handler"
require "http-session"

Log.setup_from_env(default_level: :debug)

auth_handler = OpenIDConnect::AuthHandler.new do |context, id_token, access_token|
  context.response.puts "Hello #{id_token.json_unmapped["given_name"]? || id_token.json_unmapped["email"]?}"
end

server = HTTP::Server.new([HTTP::ErrorHandler.new, HTTP::LogHandler.new, auth_handler]) do |context|
  auth_handler.authorize!(context)
end

address = server.bind_tcp 0

auth_handler.provider = OpenIDConnect::Provider.new(
  "https://keycloak.rabanus.kath.de/auth/realms/kath.de",
  authorize_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/auth",
  token_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/token",
  userinfo_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/userinfo",
  client_id: "oidc-crystal-test",
  client_secret: "142b6a06-7fe3-42d0-83d3-5b7abe4a8405",
  redirect_uri: "http://#{address}/openid_redirect",
  public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg861vbe62w85fP4TzZwn+Dq7C97b/Wbt82E7QinvlBRE8FuvC5ZJDluqmgjK2GMz9GainmyEL4XumdZvQXJ8yXAD+0JNzZ4iZZpCXyPaza10U1RWBub9OX/6cOyZ+ZKRM/zJ+AOBIlIQoJkilwFL+U3TvOoDD7POP+v1A86D51pCAKGOT+W+gVFZb/uO0IKYzK6yPgZ47whgGfZ9A/2e5ALEIBvhjQuLbHi7jNj6lQDEBdogU7yMEu91i/3w0E7tcgAM++2/VQvg06viZWBzHG8E2k+jmFqo95gIg3xr3rXT2CRRXBzD01juMNJkPnW05VrCp/pcNDM3mtcRxEIe4wIDAQAB\n-----END PUBLIC KEY-----"
)

puts "Listening on http://#{address}"

Signal::INT.trap do
  server.close unless server.closed?
  exit
end

server.listen
