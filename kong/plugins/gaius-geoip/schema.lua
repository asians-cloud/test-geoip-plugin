local typedefs = require "kong.db.schema.typedefs"

return {
  name = "gaius-geoip",
  fields = {
    { config = {
      type = "record",
      fields = {
        { inject_country_header = { type = "string", default = "X-COUNTRY" }, },
        { whitelist_countries = { type = "array", elements = {type = "string" } }, },
        { blacklist_countries = { type = "array", elements = {type = "string" } }, },
        { mode = {
          type = "string",
          default = "Blacklist",
          one_of = { "Whitelist", "Blacklist" },
          }, 
        },
        { whitelist_ips = { type = "array", elements = typedefs.ip_or_cidr, } },
      }
    }},
  }
}
