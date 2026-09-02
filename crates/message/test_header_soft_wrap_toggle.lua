local kumo = require 'kumo'

local function new_msg()
  return kumo.make_message(
    'sender@example.com',
    'recip@example.com',
    'Subject: hello\r\n\r\nHello'
  )
end

local long_value = string.rep('hello there ', 10):gsub('%s+$', '')

-- Default: soft wrap enabled, so append_header/prepend_header with
-- encode=true fold long, space-separated values with \r\n\t.
local msg = new_msg()
msg:append_header('X-Append-Wrap', long_value, true)
msg:prepend_header('X-Prepend-Wrap', long_value, true)
local parsed = msg:parse_mime()
assert(
  parsed.headers:get_first_named('X-Append-Wrap').raw_value:find '\r\n\t',
  'expected append_header to soft wrap by default'
)
assert(
  parsed.headers:get_first_named('X-Prepend-Wrap').raw_value:find '\r\n\t',
  'expected prepend_header to soft wrap by default'
)

-- With the global toggle disabled, append_header/prepend_header with
-- encode=true no longer fold at soft width, even though they still
-- explicitly request encoding.
kumo.set_header_soft_wrap_enabled(false)
local msg2 = new_msg()
msg2:append_header('X-Append-NoWrap', long_value, true)
msg2:prepend_header('X-Prepend-NoWrap', long_value, true)
local parsed2 = msg2:parse_mime()
local utils = require 'policy-extras.policy_utils'
utils.assert_eq(
  parsed2.headers:get_first_named('X-Append-NoWrap').raw_value,
  long_value
)
utils.assert_eq(
  parsed2.headers:get_first_named('X-Prepend-NoWrap').raw_value,
  long_value
)

kumo.set_header_soft_wrap_enabled(true)
