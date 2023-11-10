-- ref = "git://github.com/dontmint/kong-geoip.git"

package = "gaius-geoip-plugin"
version = "0.3.0-0"
supported_platforms = {"linux", "macosx"}

source = {
  url = "git@github.com:asians-cloud/kong-plugins.git",
  tag = "master"
}

description = {
  summary = "HTTP GEO info and ban for Kong, Customerize By Gaius",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.gaius-geoip.maxminddb"]         = "kong/plugins/gaius-geoip/maxminddb.lua",
    ["kong.plugins.gaius-geoip.handler"]           = "kong/plugins/gaius-geoip/handler.lua",
    ["kong.plugins.gaius-geoip.schema"]            = "kong/plugins/gaius-geoip/schema.lua",
  }
}
