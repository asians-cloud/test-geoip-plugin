local typedefs = require "kong.db.schema.typedefs"
local utils = require "kong.tools.utils"

local schema = {
  name = "gaius-geoip",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          { inject_country_header = { type = "string", default = "X-COUNTRY" }, },
          { whitelist_countries = { type = "array", elements = { type = "string" } }, },
          { blacklist_countries = { type = "array", elements = { type = "string" } }, },
          {
            mode = {
              type = "string",
              default = "Blacklist",
              one_of = { "Whitelist", "Blacklist" },
            },
          },
          { whitelist_ips = { type = "array", elements = typedefs.ip_or_cidr, } },
        },
      },
    },
  },
  entity_checks = {
    { at_least_one_of = { "config.whitelist_countries", "config.blacklist_countries" } },
    {
      custom_entity_check = {
        field_sources = { "config" },
        fn = function(entity)
          local config = entity.config
          local ips_or_cidrs = config.whiltelist_ips
          if ips_or_cidrs == nil or #ips_or_cidrs == 0 then
            return true
          end

          for _, ip_or_cidr in ipairs(ips_or_cidrs) do
            if utils.validate_ip_or_cidr(ip_or_cidr) then -- luacheck: ignore
              -- do nothing
            else
              return false
            end
          end
          return true
        end
      }
    }
  },
}

return schema
