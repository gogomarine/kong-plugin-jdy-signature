local typedefs = require "kong.db.schema.typedefs"


local PLUGIN_NAME = "jdy-signature"


local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        fields = {
          { hide_credentials = { type = "boolean", required = true, default = false }, },
          { clock_skew = { type = "number", default = 300, gt = 0 }, },
          { jdy_consumer_id = { type = "string"}, },
        },
      },
    },
  },
}

return schema
