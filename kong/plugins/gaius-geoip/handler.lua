local ngx        = require "ngx"
local geo        = require 'kong.plugins.gaius-geoip.maxminddb'
local ipmatcher  = require "resty.ipmatcher"

local MMDB_PATH  = "/usr/share/GeoLite2-Country.mmdb"

local GaiusGeoIP = {
  PRIORITY = 2050,
  VERSION  = "0.3.0",
}

local BLACKLIST  = "blacklist"
local WHITELIST  = "whitelist"

-- copy from https://github.com/api7/lua-resty-ipmatcher/blob/3e93c53eb8c9884efe939ef070486a0e507cc5be/t/sanity.t#L192
-- TODO: Study and find correct ways to mock ngx.var fields
--
-- Copying this method is to generate the binary remote address for test purpsoes

-- function get_ip_bin(ip)
--   local sock = ngx.socket.tcp()
--   sock:settimeout(100)
--
--   local ok, err = sock:connect("192.168.50.50", 55000)
--   if not ok then
--     kong.log.err("failed to connect: " .. err)
--     return
--   end
--
--   local req = "GET /foo HTTP/1.0\r\nHost: test.com\r\nConnection: close\r\nX-Real-IP:" .. ip .. "\r\n\r\n"
--   local bytes, err = sock:send(req)
--   if not bytes then
--     kong.log.err("failed to send http request: " .. err)
--     return
--   end
--
--   -- skip http header
--   while true do
--     local data, err, _ = sock:receive('*l')
--     if err then
--       kong.log.err('unexpected error occurs when receiving http head: ' .. err)
--       return
--     end
--     if #data == 0 then -- read last line of head
--       break
--     end
--   end
--
--   local data, err = sock:receive('*a')
--   sock:close()
--   if not data then
--     kong.log.err("failed to receive body: " .. err)
--   end
--   return data
-- end

local match_bin  = function(list, binary_remote_addr)
  local ip, err = ipmatcher.new(list)
  if err then
    return error("failed to create a new ipmatcher instance: " .. err)
  end

  local is_match
  is_match, err = ip:match_bin(binary_remote_addr)
  if err then
    return error("invalid binary ip address: " .. err)
  end

  return is_match
end

function GaiusGeoIP:init_worker()
  kong.log.info("GaiusGeoIP init_worker")
  geo.init(MMDB_PATH)
end

---
--- full :{"city":{"geoname_id":1799962,"names":{"en":"Nanjing","ru":"Нанкин","fr":"Nankin","pt-BR":"Nanquim","zh-CN":"南京","es":"Nankín","de":"Nanjing","ja":"南京市"}},"subdivisions":[{"geoname_id":1806260,"names":{"en":"Jiangsu","fr":"Province de Jiangsu","zh-CN":"江苏省"},"iso_code":"32"}],"country":{"geoname_id":1814991,"names":{"en":"China","ru":"Китай","fr":"Chine","pt-BR":"China","zh-CN":"中国","es":"China","de":"China","ja":"中国"},"iso_code":"CN"},"registered_country":{"geoname_id":1814991,"names":{"en":"China","ru":"Китай","fr":"Chine","pt-BR":"China","zh-CN":"中国","es":"China","de":"China","ja":"中国"},"iso_code":"CN"},"location":{"time_zone":"Asia\/Shanghai","longitude":118.7778,"accuracy_radius":50,"latitude":32.0617},"continent":{"geoname_id":6255147,"names":{"en":"Asia","ru":"Азия","fr":"Asie","pt-BR":"Ásia","zh-CN":"亚洲","es":"Asia","de":"Asien","ja":"アジア"},"code":"AS"}}
---

-- Access Phase
function GaiusGeoIP:access(conf)
  local binary_remote_addr = ngx.var.binary_remote_addr
  local remote_addr = ngx.var.remote_addr
  -- TODO: need to address the mock on two variables above for test
  -- local remote_addr = "118.232.111.89"
  -- local binary_remote_addr = get_ip_bin(remote_addr)
  if not binary_remote_addr then
    return kong.response.error(403, "Cannot identify the client IP address, unix domain sockets are not supported.")
  end

  -- Global ip restriction allowed
  if kong.ctx.shared.is_trusted then
    return
  end

  if remote_addr == "127.0.0.1" then
    return
  end

  local geoinfo = geo.lookup(remote_addr)
  if geoinfo == nil then
    kong.log.err("Plugin DEBUG message : nil geoinfo: ", remote_addr)
    return
  end

  local country = geoinfo.country
  if country == nil then
    kong.log.err("Plugin DEBUG message : Country not found : ", remote_addr)
    return
  end

  -- INJECT HEADER
  if conf.inject_country_header ~= nil then
    kong.response.set_header(conf.inject_country_header, country.iso_code)
  end

  -- BLOCK IP IF MATCH RULES
  local block = 0
  if string.lower(conf.mode) == BLACKLIST and conf.blacklist_countries ~= nil then
    for _, line in ipairs(conf.blacklist_countries) do
      if line == country.iso_code then
        block = 1
      end
    end
  elseif string.lower(conf.mode) == WHITELIST then
    block = 1
    if conf.whitelist_countries ~= nil then
      for _, line in ipairs(conf.whitelist_countries) do
        if line == country.iso_code then
          block = 0
        end
      end
    end
  end

  if block == 1
      and conf.whitelist_ips
      and #conf.whitelist_ips > 0
      and match_bin(conf.whitelist_ips, binary_remote_addr) then
    block = 0
  end


  if block == 1 then
    kong.response.set_header("x-geoip", "BLOCKED")
    kong.response.exit(403, "Access not available for your ip: " .. remote_addr .. ", " .. country.iso_code)
  end
end

return GaiusGeoIP
