-- principal.lua — project the validated JWT claims into the `x-kx-principal` header.
--
-- This is the whole of what the proxy contributes to identity, and it is deliberately visible rather than
-- buried in a filter option: jwt_authn has already VERIFIED the signature against Keycloak's JWKS, and
-- this turns the verified claims into the JSON shape `kx.auth` promotes. q does no crypto and parses no
-- token; it trusts this header because of the connection it arrived on AND because the proxy's login holds
-- `assert on `kx.identity.
--
-- Why Lua rather than jwt_authn's own claim_to_headers: that option copies SCALAR claims into separate
-- headers, and `serveHttp` wants one JSON object (fromJson:{promote .j.k x}). Groups are an array, so a
-- projection step is unavoidable — and having it here means a reader can see exactly which claims become
-- identity and which are ignored.
--
-- STRIP-THEN-SET (spec constraint 2). The route decides, via route filter metadata, whether this filter
-- removes a client-supplied header before adding its own:
--
--   metadata: {filter_metadata: {envoy.filters.http.lua: {strip_client_principal: true}}}
--
-- With the strip, exactly one `x-kx-principal` reaches q — the proxy's. WITHOUT it, the client's header
-- survives and this filter APPENDS a second one; kdb+ presents both to `.z.ph` as two dict entries and
-- `serveHttp` matches the FIRST, so the client's value wins and the caller becomes anyone. That is the
-- same class of defect as trusting a client-supplied X-Forwarded-For, no module code can prevent it, and
-- the demo's :10001 listener exists to show it landing.

local ESCAPES = { ['"'] = '\\"', ['\\'] = '\\\\', ['\b'] = '\\b', ['\f'] = '\\f',
                  ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }

local function esc(v)
  local s = tostring(v)
  s = s:gsub('[%c"\\]', function(c)
    return ESCAPES[c] or string.format('\\u%04x', string.byte(c))
  end)
  return s
end

local function json_string(v)
  return '"' .. esc(v) .. '"'
end

local function json_array(values)
  local parts = {}
  for i = 1, #values do
    parts[i] = json_string(values[i])
  end
  return '[' .. table.concat(parts, ',') .. ']'
end

-- Keycloak puts REALM ROLES in realm_access.roles and needs no mapper to do it. `kx.auth.promote` would in
-- fact find them there itself (its default group search order is groups, then realm_access.roles, then
-- roles), so projecting them into a flat `groups` array here is a choice for legibility, not a necessity.
local function roles_of(payload)
  local realm = payload["realm_access"]
  if type(realm) ~= "table" then
    return {}
  end
  local roles = realm["roles"]
  if type(roles) ~= "table" then
    return {}
  end
  return roles
end

-- Keycloak's `sub` is an opaque user UUID. A gateway is exactly the right place to decide that the
-- deployment's notion of a subject is the login name, so prefer preferred_username and fall back to sub.
-- The audit trail in q then reads `alice` rather than a UUID, and policies key on groups regardless.
local function subject_of(payload)
  local preferred = payload["preferred_username"]
  if type(preferred) == "string" and #preferred > 0 then
    return preferred
  end
  return payload["sub"]
end

local function principal_json(payload)
  local parts = {}
  local sub = subject_of(payload)
  if sub ~= nil then
    parts[#parts + 1] = '"sub":' .. json_string(sub)
  end
  parts[#parts + 1] = '"groups":' .. json_array(roles_of(payload))
  if payload["iss"] ~= nil then
    parts[#parts + 1] = '"iss":' .. json_string(payload["iss"])
  end
  -- Forwarding `exp` as unix seconds is load-bearing: promote[] canonicalises it to a timestamp and
  -- valid[] then refuses an expired principal. Drop it and a proxy-asserted identity would never expire.
  if type(payload["exp"]) == "number" then
    parts[#parts + 1] = '"exp":' .. string.format("%d", payload["exp"])
  end
  return '{' .. table.concat(parts, ',') .. '}'
end

function envoy_on_request(handle)
  local metadata = handle:streamInfo():dynamicMetadata():get("envoy.filters.http.jwt_authn")
  if metadata == nil then
    return
  end
  local payload = metadata["jwt_payload"]
  if type(payload) ~= "table" then
    return
  end

  local route_meta = handle:metadata()
  if route_meta ~= nil and route_meta:get("strip_client_principal") then
    -- STRIP. Then set, below. Miss this line and identity is forgeable.
    handle:headers():remove("x-kx-principal")
  end
  handle:headers():add("x-kx-principal", principal_json(payload))
end
