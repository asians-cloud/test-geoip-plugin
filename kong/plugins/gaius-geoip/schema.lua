local typedefs = require "kong.db.schema.typedefs"

-- Suresh G : using more optimized way of Type Declarations.
-- It enhances code readability and manageability.

local string_type = typedefs.type_string
local array_of_strings = typedefs.array_of_strings
local ip_cidr = typedefs.ip_or_cidr

return {
  name = "gaius-geoip",
  fields = {
    { config = {
      type = "record",
      fields = {
        { inject_country_header = { type = string_type, default = "X-COUNTRY" }, },
        { whitelist_countries = { type = array_of_strings }, },
        { blacklist_countries = { type = array_of_strings }, },
        { mode = {
          type = string_type,
          default = "Blacklist",
          one_of = { "Whitelist", "Blacklist" },
          },
        },
        { whitelist_ips = { type = array_of_strings, elements = ip_cidr, } },
      }
    }},
  }
}
