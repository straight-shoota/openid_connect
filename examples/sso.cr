require "../src/openid_connect"
require "http"

Log.setup_from_env(default_level: :debug)

auth_handler = OpenIDConnect::AuthHandler.new do |context, id_token, access_token, provider|
  userinfo = provider.get_userinfo(id_token, access_token)
  print_id_token(context, id_token, access_token, userinfo)
end

server = HTTP::Server.new([HTTP::ErrorHandler.new, HTTP::LogHandler.new, auth_handler]) do |context|
  case context.request.path
  when "/"
    auth_handler.authorize!(context)
    next
  end
end

address = server.bind_tcp 0

auth_handler.provider = OpenIDConnect::Provider.new(
  URI.parse("https://keycloak.rabanus.kath.de/auth/realms/kath.de"),
  authorize_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/auth",
  token_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/token",
  userinfo_endpoint: "https://keycloak.rabanus.kath.de/auth/realms/kath.de/protocol/openid-connect/userinfo",
  client_id: "oidc-crystal-test",
  client_secret: "142b6a06-7fe3-42d0-83d3-5b7abe4a8405",
  redirect_uri: "http://#{address}/openid_redirect",
  public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg861vbe62w85fP4TzZwn+Dq7C97b/Wbt82E7QinvlBRE8FuvC5ZJDluqmgjK2GMz9GainmyEL4XumdZvQXJ8yXAD+0JNzZ4iZZpCXyPaza10U1RWBub9OX/6cOyZ+ZKRM/zJ+AOBIlIQoJkilwFL+U3TvOoDD7POP+v1A86D51pCAKGOT+W+gVFZb/uO0IKYzK6yPgZ47whgGfZ9A/2e5ALEIBvhjQuLbHi7jNj6lQDEBdogU7yMEu91i/3w0E7tcgAM++2/VQvg06viZWBzHG8E2k+jmFqo95gIg3xr3rXT2CRRXBzD01juMNJkPnW05VrCp/pcNDM3mtcRxEIe4wIDAQAB\n-----END PUBLIC KEY-----"
)

puts "Listening on http://#{address}"

server.listen

def print_id_token(context, id_token, access_token, userinfo)
  context.response << "<html><body>"
  context.response << "ID Token"
  context.response << "<table>"
  {% for ivar in OpenIDConnect::IDToken.instance_vars %}
    {% unless ivar.id == "json_unmapped" %}
      context.response << "<tr>"
      context.response << "<th>{{ ivar }}</th>"
      context.response << "<td>" << id_token.{{ ivar }} << "</td>"
      context.response << "</tr>"
      context.response.puts
    {% end %}
  {% end %}
  context.response << "<tr>"
  context.response << "<td colspan=\"2\">extra</td>"
  context.response << "</tr>"
  id_token.json_unmapped.each do |key, value|
    context.response << "<tr>"
    context.response << "<th>" << key << "</th>"
    context.response << "<td>" << value << "</td>"
    context.response << "</tr>"
    context.response.puts
  end
  context.response << "<td colspan=\"2\">access_token</td>"
  {% for ivar in OAuth2::AccessToken.instance_vars %}
    context.response << "<tr>"
    context.response << "<th>{{ ivar }}</th>"
    context.response << "<td>" << access_token.{{ ivar }} << "</td>"
    context.response << "</tr>"
    context.response.puts
  {% end %}
  context.response << "<tr>"
  context.response << "</table>"
  state = context.request.query_params["state"]?
  if state
    context.response << "Location: " << state << "<br/>"
  end
  context.response << "Userinfo"
  context.response << "<table>"
  userinfo.as_h.each do |key, value|
    context.response << "<tr>"
    context.response << "<th>" << key << "</th>"
    context.response << "<td>" << value << "</td>"
    context.response << "</tr>"
    context.response.puts
  end
  context.response << "</table>"
  context.response << "</html></body>"
end
