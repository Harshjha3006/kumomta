---
tags:
 - message
---

# kumo.set_header_soft_wrap_enabled

```lua
kumo.set_header_soft_wrap_enabled(enabled)
```

{{since('dev')}}

Controls whether long header values are folded across multiple lines
for readability ("soft wrap") when they are encoded via functions such
as `message:append_header`, `message:prepend_header` (when their
`encode` parameter is `true`), the HTTP injection API's JSON builder
`headers`, and `mimepart.builder():headers`.

This setting is process-wide and defaults to `true`, matching prior
behavior. Set it to `false` to disable the readability folding.

The hard-wrap safety net that prevents a single unbreakable header
value from producing a line that exceeds SMTP's maximum line length is
always applied regardless of this setting.

This setting has no effect on non-ASCII header values, which are
always RFC 2047 encoded-word wrapped regardless of this setting.

```lua
kumo.on('pre_init', function()
  kumo.set_header_soft_wrap_enabled(false)
end)
```
