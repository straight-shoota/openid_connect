require "spec"
require "../src/openid_connect"

def wait_until_blocked(f : Fiber, timeout = 5.seconds)
  now = Time.monotonic

  until f.resumable?
    Fiber.yield
    raise "fiber failed to block within #{timeout}" if (Time.monotonic - now) > timeout
  end
end

# Helper method which runs a *handler*
def run_handler(handler)
  done = Channel(Exception?).new

  begin
    IO::Stapled.pipe do |server_io, client_io|
      processor = HTTP::Server::RequestProcessor.new(handler)
      f = spawn do
        processor.process(server_io, server_io)
      rescue exc
        done.send exc
      else
        done.send nil
      end

      client = HTTP::Client.new(client_io)

      begin
        wait_until_blocked f

        yield client
      ensure
        processor.close
        server_io.close
        if exc = done.receive
          raise exc
        end
      end
    end
  end
end
