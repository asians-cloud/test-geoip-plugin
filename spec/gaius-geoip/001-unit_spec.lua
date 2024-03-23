---@diagnostic disable: undefined-field
local PLUGIN_NAME = "gaius-geoip"


-- helper function to validate data against a schema
local v = require("spec.helpers").validate_plugin_config_schema
local schema_def = require("kong.plugins." .. PLUGIN_NAME .. ".schema")

describe(PLUGIN_NAME .. ": (schema)", function()
  it("invalid schema fields", function()
    local fixtuers = {
      ["empty"] = {},
      ["miss_countries"] = { whitelist_ips = { "10.10.10.10" } }
    }
    for _, fixt in pairs(fixtuers) do
      assert.falsy(v(fixt, schema_def))
    end
  end)

  it("minimum fields", function()
    local fixtures = {
      ["whitelist_countries"] = { whitelist_countries = { "USA", "UK" }, },
      ["blacklist_countries"] = { blacklist_countries = { "USA", "UK" }, }
    }
    for _, fixt in pairs(fixtures) do
      assert(v(fixt, schema_def))
    end
  end)

  it("invalid ip format for whitelist_ip", function()
    local invalid_ips = {
      "10.10.10.10.10",
      ".10.10.10.10",
      192,
      "10.10.0.0/166",
      "10.0.0",
      "localhost"
    }
    for _, _ip in pairs(invalid_ips) do
      assert.falsy(
        v(
          {
            blacklist_countries = { "USA" },
            whitelist_ips = { _ip },
          },
          schema_def
        )
      )
    end
  end)

  it("valid whitelist_ips", function()
    assert(
      v(
        {
          whitelist_countries = { "USA" },
          whitelist_ips = {
            "10.10.10.10",
            "10.10.0.0/16",
            "192.168.0.1/24",
          },
        },
        schema_def
      )
    )
  end)
end)
