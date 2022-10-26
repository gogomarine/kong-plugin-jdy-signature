local constants = require "kong.constants"
local sha1 = require "resty.sha1"
local utils = require "kong.tools.utils"


local ngx = ngx
local kong = kong
local error = error
local time = ngx.time
local abs = math.abs
local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64
local ipairs = ipairs
local fmt = string.format
local string_lower = string.lower
local kong_request = kong.request
local kong_client = kong.client
local kong_service_request = kong.service.request

local str = require "resty.string"

-- X-JDY-Signature为签名内容，使用方式在下面的签名验证内容中会提到。
local X_JDY_SIGNATURE = "X-JDY-Signature"
-- X-JDY-DeliverId 为推送事件ID，每次推送的id是唯一的。可以通过该字段完成请求的去重，防止重复接收同一个事件。
local X_JDY_DELIVERID = "X-JDY-DeliverId"
-- 时间戳参数
local PARAM_TIMESTAMP = "timestamp"
-- 临时盐
local PARAM_NONCE = "nonce"
local SIGNATURE_NOT_VALID = "signature cannot be verified"
local SIGNATURE_NOT_SAME = "signature does not match!!!"


-- plugin assumes the request parameters being used for creating
-- signature by client are not changed by core or any other plugin
local function create_hash(hmac_params)
  local pms = {hmac_params.nonce, hmac_params.body, hmac_params.secret, hmac_params.timestamp}

  local content = table.concat(pms, ':')

  local digest = ngx.sha1_bin(content or '')

  -- kong.response.error(400, 'current content digest '..content .. '=>'.. str.to_hex(digest))

  return str.to_hex(digest)
end


local function validate_signature(hmac_params, signature)
  local signature_1 = create_hash(hmac_params)
  return signature_1 == signature
end


local function load_credential_into_memory(username)
  local key, err = kong.db.hmacauth_credentials:select_by_username(username)
  if err then
    return nil, err
  end
  return key
end


local function load_credential(username)
  local credential, err
  if username then
    local credential_cache_key = kong.db.hmacauth_credentials:cache_key(username)
    credential, err = kong.cache:get(credential_cache_key, nil,
                                     load_credential_into_memory,
                                     username)
  end

  if err then
    return error(err)
  end

  return credential
end

-- print(string.format("%s, %s, %s, %s", ngx.time(), os.time(), os.clock(), ngx.now()))
-- ngx.exit(200)
-- 以上代码会输出： 1486971340, 1486971340, 209.77, 1486971340.422


local function validate_clock_skew(requestTime, allowed_clock_skew)
  if not requestTime then
    return false
  end

  local skew = abs(time() - requestTime)
  if skew > allowed_clock_skew then
    return false
  end

  return true
end


local function set_consumer(consumer, credential)
  kong_client.authenticate(consumer, credential)

  local set_header = kong_service_request.set_header
  local clear_header = kong_service_request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.username then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.username)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
  end

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end


local function do_authentication(conf)
  local jdyDeliverId = kong_request.get_header(X_JDY_DELIVERID)
  local jdySignature = kong_request.get_header(X_JDY_SIGNATURE)

  -- If both headers are missing, return 401
  if not (jdyDeliverId or jdySignature) then
    return false, { status = 401, message = "Unauthorized" }
  end

  -- validate timestamp exists
  local timestamp = kong_request.get_query_arg(PARAM_TIMESTAMP)
  local nonce = kong_request.get_query_arg(PARAM_NONCE)
  -- If both headers are missing, return 401
  if not (timestamp or nonce) then
    return false, { status = 401, message = "Unauthorized, timestamp or nonce is missing" }
  end

  -- validate clock skew
  if not (validate_clock_skew(timestamp, conf.clock_skew)) then
    return false, {
      status = 401,
      message = "signature cannot be verified, a valid timestamp is required"
    }
  end

  -- load credential for jdy consumer id
  local credential = load_credential(conf.jdy_consumer_id)
  if not credential then
    kong.log.debug("failed to retrieve credential for ", conf.jdy_consumer_id)
    return false, { status = 401, message = SIGNATURE_NOT_VALID }
  end

  -- verified body
  local body, err = kong_request.get_raw_body()
  if err then
    kong.log.debug(err)
    return false, { status = 401, message = SIGNATURE_NOT_VALID }
  end

  -- create param map
  local hmac_params = {}
  hmac_params.timestamp = timestamp
  hmac_params.nonce = nonce
  hmac_params.body = body or ''
  hmac_params.secret = credential.secret
  hmac_params.signing_params = {'nonce', 'body', 'secret', 'timestamp'}  -- 参数个数

  if not validate_signature(hmac_params, jdySignature) then
    return false, { status = 401, message = SIGNATURE_NOT_SAME }
  end

  -- Retrieve consumer
  local consumer_cache_key, consumer
  consumer_cache_key = kong.db.consumers:cache_key(credential.consumer.id)
  consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                      kong_client.load_consumer,
                                      credential.consumer.id)
  if err then
    return error(err)
  end

  set_consumer(consumer, credential)

  return true
end


local _M = {}


function _M.execute(conf)
  -- 如果已经认证，忽略，比如说已经
  -- if kong_client.get_credential() then
  --   -- we're already authenticated, and we're configured for using anonymous,
  --   -- hence we're in a logical OR between auth methods and we're already done.
  --   -- 如果允许匿名访问，并且当前可以获取，详情查看：https://docs.konghq.com/gateway/latest/plugin-development/pdk/kong.client/#kongclientget_credential
  --   return
  -- end

  local ok, err = do_authentication(conf)
  if not ok then
    if not err then
      err = { status = 401, message = SIGNATURE_NOT_VALID }
    end
    return kong.response.error(err.status, err.message, err.headers)
  end
end


return _M
