---@diagnostic disable: undefined-field

local helpers = require "spec.helpers"

local PLUGIN_NAME = "gaius-geoip"

for _, strategy in helpers.all_strategies() do
  if strategy == "postgres" then
    describe("Plugin: " .. PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
      lazy_setup(function()
        helpers.setenv("NODE_ENV", "test")
        local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })
        local route1 = bp.routes:insert({
          hosts = { "test1.com" },
        })
        local route2 = bp.routes:insert({
          hosts = { "test2.com" },
        })
        local route3 = bp.routes:insert({
          hosts = { "test3.com" },
        })
        local route4 = bp.routes:insert({
          hosts = { "test4.com" },
        })
        local route5 = bp.routes:insert({
          hosts = { "test5.com" },
        })
        bp.plugins:insert {
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            -- both country code and ip are whitelisted
            whitelist_countries = { "TW" },
            mode = "Whitelist",
            whitelist_ips = { "118.232.111.89" }
          },
        }
        bp.plugins:insert {
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            -- country code isn't in the list whillisted IPs
            whitelist_countries = { "US" },
            mode = "Whitelist",
            whitelist_ips = { "118.232.111.89/32" }
          },
        }
        bp.plugins:insert {
          name = PLUGIN_NAME,
          route = { id = route3.id },
          config = {
            -- both country code and ip are blacklisted
            blacklist_countries = { "TW" },
            mode = "Blacklist",
            whitelist_ips = { "118.232.111.89" }
          },
        }
        bp.plugins:insert {
          name = PLUGIN_NAME,
          route = { id = route4.id },
          config = {
            -- ip banned matches no country code in the blacklist
            blacklist_countries = { "US" },
            mode = "Blacklist",
            whitelist_ips = { "118.232.111.89" }
          },
        }
        bp.plugins:insert {
          name = PLUGIN_NAME,
          route = { id = route5.id },
          config = {
            -- whitelisted countries not in allowed country codes
            whitelist_countries = { "US" },
            mode = "Whitelist",
            whitelist_ips = {}
          },
        }
        assert(helpers.start_kong({
          database   = strategy,
          nginx_conf = "spec/fixtures/custom_nginx.template",
          plugins    = "bundled," .. PLUGIN_NAME,
        }))
      end)

      lazy_teardown(function()
        helpers.stop_kong(nil, true)
      end)

      local client
      before_each(function()
        client = helpers.proxy_client()
      end)

      after_each(function()
        if client then client:close() end
      end)

      describe("allowed", function()
        it("country and ip", function()
          local r = client:get("/request", {
            headers = {
              ["Host"] = "test1.com",
            }
          })
          assert.response(r).has.status(200)
        end)
        it("blackedlist country", function()
          local r = client:get("/request", {
            headers = {
              ["Host"] = "test4.com",
            }
          })
          assert.response(r).has.status(200)
        end)
      end)

      describe("blocked", function()
        it("coutry for banned ip", function()
          local r = client:get("/request", {
            headers = {
              ["Host"] = "test2.com",
            }
          })
          assert.response(r).has.status(403)
        end)
        it("country and ip", function()
          local r = client:get("/request", {
            headers = {
              ["Host"] = "test3.com",
            }
          })
          assert.response(r).has.status(403)
        end)
        it("whitelisted countries not in allowed country codes", function()
          local r = client:get("/request", {
            headers = {
              ["Host"] = "test5.com",
            }
          })
          assert.response(r).has.status(403)
        end)
      end)
    end)
  end
end
