local kumo = require 'kumo'
local utils = require 'policy-extras.policy_utils'

local long_value = string.rep('hello there ', 10)

local function build(name)
  local ok, msgs = pcall(kumo.api.inject.build_v1, {
    envelope_sender = 'no-reply@example.com',
    recipients = {
      { email = 'user@example.com' },
    },
    content = {
      text_body = 'Hello',
      headers = { [name] = long_value },
    },
  })
  assert(ok, tostring(msgs))
  return msgs[1]
end

-- Default: soft wrap is enabled, so a long, space-separated header
-- value gets folded with \r\n\t.
local wrapped = build 'X-Soft-Wrap-Default'
local raw = wrapped:parse_mime().headers:get_first_named('X-Soft-Wrap-Default').raw_value
assert(
  raw:find '\r\n\t',
  'expected default behavior to soft wrap, got: ' .. raw
)

kumo.set_header_soft_wrap_enabled(false)
local unwrapped = build 'X-Soft-Wrap-Disabled'
local raw_unwrapped =
  unwrapped:parse_mime().headers:get_first_named('X-Soft-Wrap-Disabled').raw_value
utils.assert_eq(raw_unwrapped, long_value:gsub('%s+$', ''))

kumo.set_header_soft_wrap_enabled(true)
local rewrapped = build 'X-Soft-Wrap-Reenabled'
local raw_rewrapped =
  rewrapped:parse_mime().headers:get_first_named('X-Soft-Wrap-Reenabled').raw_value
assert(
  raw_rewrapped:find '\r\n\t',
  'expected soft wrap to resume once re-enabled, got: ' .. raw_rewrapped
)
