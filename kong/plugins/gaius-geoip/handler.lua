-- Suresh G : Organized the Top header section in a better and readable manner, by clubbing declarations etc suitably.
-- It is easy to read and interpret, Overall better manageability.

local geo = require 'kong.plugins.gaius-geoip.maxminddb'
local ipmatcher = require "resty.ipmatcher"

local MMDB_PATH = "/GeoLite2-Country.mmdb"

local kong = kong

local response = kong.response

local GaiusGeoIP = {
  PRIORITY = 2050,
  VERSION  = "0.3.0",
}

-- Suresh G : Created local variable instances to replace  the repititive global seeks.
-- It can help in better performance by caching the data locally and then iterating over local vaiables.

local ngx_var = ngx.var
local is_trusted = kong.ctx.shared.is_trusted

function match_bin(list, binary_remote_addr)
  -- Suresh G : Removed unnecessary additional step of creating a new ipmatcher instance.
  -- It can be done in a single step call by calling ipmatcher match on list directly.

  local is_match, err = ipmatcher.match(list,binary_remote_addr)
  if err then
    return error("invalid binary ip address: " .. err)
  end

  return is_match  
end

function GaiusGeoIP:init_worker()
  kong.log.info("GaiusGeoIP init_worker")
end

---
--- full :{"city":{"geoname_id":1799962,"names":{"en":"Nanjing","ru":"Нанкин","fr":"Nankin","pt-BR":"Nanquim","zh-CN":"南京","es":"Nankín","de":"Nanjing","ja":"南京市"}},"subdivisions":[{"geoname_id":1806260,"names":{"en":"Jiangsu","fr":"Province de Jiangsu","zh-CN":"江苏省"},"iso_code":"32"}],"country":{"geoname_id":1814991,"names":{"en":"China","ru":"Китай","fr":"Chine","pt-BR":"China","zh-CN":"中国","es":"China","de":"China","ja":"中国"},"iso_code":"CN"},"registered_country":{"geoname_id":1814991,"names":{"en":"China","ru":"Китай","fr":"Chine","pt-BR":"China","zh-CN":"中国","es":"China","de":"China","ja":"中国"},"iso_code":"CN"},"location":{"time_zone":"Asia\/Shanghai","longitude":118.7778,"accuracy_radius":50,"latitude":32.0617},"continent":{"geoname_id":6255147,"names":{"en":"Asia","ru":"Азия","fr":"Asie","pt-BR":"Ásia","zh-CN":"亚洲","es":"Asia","de":"Asien","ja":"アジア"},"code":"AS"}}
---

-- Access Phase
function GaiusGeoIP:access(conf)
  geo.init(MMDB_PATH)

  -- Suresh G : Created local variable instances to replace  the repititive global seeks.
  -- It can help in better performance by caching the data locally and then iterating over local vaiables.

  local binary_remote_addr = ngx_var.binary_remote_addr
  local remote_addr = ngx_var.remote_addr

  -- Suresh G : Combined If conditions on remote address and binary remote address checkes into one.
  -- This will increase code readability & manageability also will enhance performance.

  if not binary_remote_addr or remote_addr == "127.0.0.1" then
    return response.error(403, "Cannot identify the client IP address, unix domain sockets are not supported Or The client IP adrress denotes Localhost.")
  end

  -- Global ip restriction allowed
  if is_trusted then
    return
  end

  local geoinfo = geo.lookup(remote_addr)

  if not geoinfo or not geoinfo.country or not geoinfo.country.iso_code then
    kong.log.err("Plugin DEBUG message: Country information not found: ", remote_addr)
    return
  end

  local country = geoinfo.country

  -- Suresh G : Created local variable instances to replace  the repititive global seeks.
  -- It can help in better performance by caching the data locally and then iterating over local vaiables.

  local mode = conf.mode
  local inject_country_header = conf.inject_country_header

  -- INJECT HEADER 
  if inject_country_header then
    response.set_header(inject_country_header, country.iso_code)
  end

  -- Suresh G : Created local variable instances to replace  the repititive global seeks.
  -- It can help in better performance by caching the data locally and then iterating over local vaiables.

  local block = 0
  local blacklist_countries = conf.blacklist_countries or {}
  local whitelist_countries = conf.whitelist_countries or {}
  local whitelist_ips = conf.whitelist_ips or {}

  -- BLOCK IP IF MATCH RULES
  
  -- Suresh G : Created numeric for loop instead of array iterations and using local valariable for iterations
  -- Numeric loops are always faster than iterating through array-like tables.
  -- Use of local variables is faster than global table iterations

  if ( mode == "Blacklist" and blacklist_countries) then 
    for i = 1, #blacklist_countries do
      local line = blacklist_countries[i]
      if line == country.iso_code then
          block = 1
          break
      end
    end

  -- Suresh G : Created numeric for loop instead of array iterations and using local valariable for iterations. Also clubbed If conditions as single statement
  -- Numeric loops are always faster than iterating through array-like tables.
  -- Use of local variables is faster than global table iterations
  -- Combining the second If condition reduced nesting depth, helping in better code readability and also helps in better performance
  elseif ( mode == "Whitelist" and whitelist_countries) then
    block = 1
    for i = 1, #whitelist_countries do
      local line = whitelist_countries[i]
      if line == country.iso_code then
          block = 0
          break
      end
    end
  end

  -- Suresh G : Clubbed If conditions as single statement and using local valariable for iterations.
  -- Combining the second If condition reduced nesting depth, helping in better code readability and also helps in better performance
  -- Use of local variables is faster than global table iterations

  if block == 1 and whitelist_ips and #whitelist_ips > 0 then
    local allowed = match_bin(whitelist_ips, binary_remote_addr)
    if allowed then
      block = 0
    end
  end

  if block == 1 then
    response.set_header("x-geoip", "BLOCKED")
    response.exit(403, "Access not available for your ip: " .. remote_addr .. ", " .. country.iso_code)
  end
end

return GaiusGeoIP