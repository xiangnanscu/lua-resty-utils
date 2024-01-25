local lfs = require("syscall.lfs")
local cjson_safe = require("cjson.safe")
local cjson = require("cjson")
local prettycjson = require "resty.prettycjson"
local array = require("resty.array")
local repr = require("resty.repr")
local dotenv = require("resty.dotenv")
local type = type
local pairs = pairs
local ipairs = ipairs
local table_sort = table.sort
local table_insert = table.insert
local table_concat = table.concat
local string_format = string.format
local select = select
local error = error
local math_floor = math.floor
local ngx_re_gsub = ngx.re.gsub
local ngx_time = ngx.time
local NULL = ngx.null
local ngx = ngx

local JSON_ENV
local function getenv(key)
  if not JSON_ENV then
    local json = dotenv { path = { '.env', '.env.local' } }
    JSON_ENV = json
  end
  if key then
    return JSON_ENV[key]
  else
    return JSON_ENV
  end
end

local function make_shared_db_proxy()
  local SHM_NAME = getenv("SHM_NAME") or "NGX_SHM"
  local db = ngx.shared[SHM_NAME]
  return {
    get = function(_, key)
      return db:get(key)
    end,
    set = function(_, key, value, exptime, flags)
      return db:set(key, value, exptime, flags)
    end,
  }
end

local db = make_shared_db_proxy()

local function writefile(s, name)
  assert(io.open(name, "a+")):write(s):close()
end
local function loger(...)
  local name = string.format("logs/%s.js", os.date("%Y%m%d-%H-%M-%S", os.time()))
  assert(io.open(name, "a+")):write(repr(...)):close()
end

local JSON_TYPE = { table = true, string = true, number = true, boolean = true }
local function copy(o, opt)
  if not opt then
    local function simple_deepcopy(v)
      if type(v) == 'table' then
        local v_copy = {}
        for key, value in pairs(v) do
          v_copy[key] = simple_deepcopy(value)
        end
        return v_copy
      else
        return v
      end
    end

    return simple_deepcopy(o)
  else
    local visited = {}
    local function recursive_copy(v)
      local v_type = type(v)
      if v_type == "table" then
        if visited[v] then
          return visited[v]
        end
        local v_copy = {}
        visited[v] = v_copy
        for key, value in pairs(v) do
          v_copy[recursive_copy(key)] = recursive_copy(value)
        end
        if opt.json then
          return v_copy
        end
        local mt = getmetatable(v)
        if not mt then
          return v_copy
        end
        if opt.copy_metatable then
          setmetatable(v_copy, recursive_copy(mt))
        else
          setmetatable(v_copy, mt)
        end
        return v_copy
      elseif JSON_TYPE[v_type] or not opt.json then
        return v
      else
        return nil
      end
    end

    return recursive_copy(o)
  end
end

local JCOPY_OPT = { json = true, copy_metatable = false }
local function jcopy(o)
  return copy(o, JCOPY_OPT)
end

local DEEPCOPY_OPT = { json = false, copy_metatable = true }
local function deepcopy(o)
  return copy(o, DEEPCOPY_OPT)
end

local function map(tbl, func)
  local res = array()
  for i = 1, #tbl do
    res[i] = func(tbl[i])
  end
  return res
end

local function filter(tbl, func)
  local res = array()
  for i = 1, #tbl do
    local v = tbl[i]
    if func(v) then
      res[#res + 1] = v
    end
  end
  return res
end

local function find(tbl, func)
  for i = 1, #tbl do
    local v = tbl[i]
    if func(v) then
      return v, i
    end
  end
end

local function mapkv(tbl, func)
  local res = {}
  for k, v in pairs(tbl) do
    k, v = func(k, v)
    res[k] = v
  end
  return res
end

local function filterkv(tbl, func)
  local res = {}
  for k, v in pairs(tbl) do
    if func(k, v) then
      res[k] = v
    end
  end
  return res
end

local function list(...)
  local t = array()
  for _, a in pairs { ... } do
    for _, v in ipairs(a) do
      t[#t + 1] = v
    end
  end
  return t
end

local function list_extend(t, ...)
  for _, a in pairs { ... } do
    for _, v in ipairs(a) do
      t[#t + 1] = v
    end
  end
  return t
end

local function list_has(t, e)
  for i, v in ipairs(t) do
    if v == e then
      return i
    end
  end
end

local function dict(...)
  local t = {}
  for _, d in pairs { ... } do
    for k, v in pairs(d) do
      t[k] = v
    end
  end
  return t
end

local function dict_update(t, ...)
  for _, a in pairs { ... } do
    for k, v in pairs(a) do
      t[k] = v
    end
  end
  return t
end

local function dict_has(t, e)
  for k, v in pairs(t) do
    if v == e then
      return true, k
    end
  end
  return false
end

local function strip(value)
  return (ngx_re_gsub(value, [[^\s*(.+)\s*$]], "$1", "josu"))
end

local function empty(value)
  return value == nil or value == "" or value == NULL
end

local function to_html_attrs(tbl)
  local attrs = {}
  local bools = {}
  for k, v in pairs(tbl) do
    if v == true then
      bools[#bools + 1] = " " .. k
    elseif v == false then
    elseif type(v) == "table" then
      attrs[#attrs + 1] = string_format(' %s="%s"', k, table_concat(v, " "))
    else
      attrs[#attrs + 1] = string_format(' %s="%s"', k, v)
    end
  end
  return table_concat(attrs, "") .. table_concat(bools, "")
end

local function reversed_inherited_chain(self)
  local res = { self }
  local cls = getmetatable(self)
  while cls do
    table.insert(res, 1, cls)
    self = cls
    cls = getmetatable(self)
  end
  return res
end

local function inherited_chain(self)
  local res = { self }
  local cls = getmetatable(self)
  while cls do
    res[#res + 1] = cls
    self = cls
    cls = getmetatable(self)
  end
  return res
end

local function sorted(t, func)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret + 1] = k
  end
  table_sort(ret, func)
  local i = 0
  return function()
    i = i + 1
    local key = ret[i]
    return key, t[key]
  end
end

local function curry(func, kwargs)
  local function _curry(morekwargs)
    return func(dict(kwargs, morekwargs))
  end

  return _curry
end

local function serialize_basetype(v)
  -- string.format("%q", '\r') 会被转义成\13, 导致浏览器渲染成13
  if type(v) == "string" then
    return '"' .. v:gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
  else
    return tostring(v)
  end
end

local function serialize_attrs(attrs, table_name)
  -- {a=1, b='bar'} -> `foo`.`a` = 1, `foo`.`b` = "bar"
  -- {a=1, b='bar'} -> a = 1, b = "bar"
  local res = {}
  if table_name then
    for k, v in pairs(attrs) do
      res[#res + 1] = string_format("%s = %s", string_format("`%s`.`%s`", table_name, k), serialize_basetype(v))
    end
  else
    for k, v in pairs(attrs) do
      res[#res + 1] = string_format("%s = %s", k, serialize_basetype(v))
    end
  end
  return table_concat(res, ", ")
end

local function split_gen(s, sep)
  sep = sep or " "
  local i = 1
  local a, b
  local stop
  local function split_iter()
    if stop then
      return
    end
    a, b = s:find(sep, i, true)
    if a then
      local e = s:sub(i, a - 1)
      i = b + 1
      return e
    else
      stop = true
      return s:sub(i)
    end
  end

  return split_iter
end

---@param s string
---@param sep? string
---@return array
local function split(s, sep)
  local res = array {}
  sep = sep or ""
  local i = 1
  local a, b
  while true do
    a, b = s:find(sep, i, true)
    if a then
      local e = s:sub(i, a - 1)
      i = b + 1
      res:push(e)
    else
      res:push(s:sub(i))
      return res
    end
  end
end

local unit_table = { s = 1, m = 60, h = 3600, d = 3600 * 24, w = 3600 * 24 * 7, M = 3600 * 24 * 30, y = 3600 * 24 * 365 }
local function time_parser(t)
  if type(t) == "string" then
    local unit = string.sub(t, -1, -1)
    local secs = unit_table[unit]
    assert(secs, "invalid time unit: " .. unit)
    local ts = string.sub(t, 1, -2)
    local num = tonumber(ts)
    assert(num, "can't convert '" .. ts .. "' to a number")
    return num * secs
  elseif type(t) == "number" then
    return t
  else
    error("invalid type:" .. type(t))
  end
end

local size_table = {
  k = 1024,
  m = 1024 * 1024,
  g = 1024 * 1024 * 1024,
  kb = 1024,
  mb = 1024 * 1024,
  gb = 1024 * 1024 * 1024
}
local function byte_size_parser(t)
  if type(t) == "string" then
    local unit = t:gsub("^(%d+)([^%d]+)$", "%2"):lower()
    local ts = t:gsub("^(%d+)([^%d]+)$", "%1"):lower()
    local bytes = size_table[unit]
    assert(bytes, "invalid size unit: " .. unit)
    local num = tonumber(ts)
    assert(num, "can't convert `" .. ts .. "` to a number")
    return num * bytes
  elseif type(t) == "number" then
    return t
  else
    error("invalid type:" .. type(t))
  end
end

local function cache(f, arg)
  local result, err
  local function _cache()
    if result == nil then
      result, err = f(arg)
    end
    return result, err
  end

  return _cache
end

local function cache_by_key(f)
  local results = {}
  local function _cache(key)
    if results[key] == nil then
      local res, err = f(key)
      if err then
        return nil, err
      end
      results[key] = res
    end
    return results[key]
  end

  return _cache
end

local function cache_by_time(f, cache_time)
  local result, err, cache_gen_time
  cache_time = time_parser(cache_time)
  if cache_time == 0 then
    return f
  end
  local function _cache()
    if result == nil or ngx_time() - cache_gen_time > cache_time then
      result, err = f()
      cache_gen_time = ngx_time()
    end
    return result, err
  end

  return _cache
end

local function locals()
  local variables = {}
  local idx = 1
  while true do
    local ln, lv = debug.getlocal(2, idx)
    if ln ~= nil then
      variables[ln] = lv
    else
      break
    end
    idx = 1 + idx
  end
  return variables
end

local function upvalues()
  local variables = {}
  local idx = 1
  local func = debug.getinfo(2, "f").func
  while true do
    local ln, lv = debug.getupvalue(func, idx)
    if ln ~= nil then
      variables[ln] = lv
    else
      break
    end
    idx = 1 + idx
  end
  return variables
end

local function zfill(s, n, c)
  local len = string.len(s)
  n = n or len
  c = c or " "
  for _ = 1, n - len do
    s = s .. c
  end
  return s
end

local function debugger(e)
  return debug.traceback() .. e
end

local function ensure_json(tbl)
  -- 确保t里面的值符合json规范
  local visited = {}
  local function f(obj)
    local e = type(obj)
    if e == "table" then
      if visited[obj] then
        return obj
      else
        visited[obj] = true
        local t = {}
        for k, v in pairs(obj) do
          if tostring(k):sub(1, 1) ~= "_" then
            t[k] = f(v)
          end
        end
        return t
      end
    elseif JSON_TYPE[e] then
      return obj
    end
  end

  return f(tbl)
end

local function compose_funcs(f, g)
  local function inner(v)
    local err
    v, err = f(v)
    if err ~= nil then
      return nil, err
    else
      return g(v)
    end
  end

  return inner
end

local function utf8len(s)
  local _, cnt = s:gsub("[^\128-\193]", "")
  return cnt
end

local function utf8charbytes(s, i)
  -- 返回从字符串s中第i个字节开始的UTF-8字符的字节数
  local c = s:byte(i)

  -- 单字节字符
  if c > 0 and c <= 127 then
    return 1
    -- 双字节字符
  elseif c >= 194 and c <= 223 then
    return 2
    -- 三字节字符
  elseif c >= 224 and c <= 239 then
    return 3
    -- 四字节字符
  elseif c >= 240 and c <= 244 then
    return 4
  end
end

local function utf8sub(s, m, n)
  local currentChar = 1
  local currentIndex = 1

  while currentIndex <= #s do
    if currentChar == m then
      break
    end
    local charBytes = utf8charbytes(s, currentIndex)

    currentIndex = currentIndex + charBytes
    currentChar = currentChar + 1
  end

  local subStart = currentIndex

  while currentIndex <= #s and currentChar <= n do
    local charBytes = utf8charbytes(s, currentIndex)
    currentIndex = currentIndex + charBytes
    currentChar = currentChar + 1
  end

  local subEnd = currentIndex - 1

  return s:sub(subStart, subEnd)
end


local Chars = {}
for Loop = 0, 255 do
  Chars[Loop + 1] = string.char(Loop)
end
local String = table.concat(Chars)

local Built = { ["."] = Chars }

local AddLookup = function(CharSet)
  local Substitute = string.gsub(String, "[^" .. CharSet .. "]", "")
  local Lookup = {}
  for Loop = 1, string.len(Substitute) do
    Lookup[Loop] = string.sub(Substitute, Loop, Loop)
  end
  Built[CharSet] = Lookup

  return Lookup
end

local function random_string(Length, CharSet)
  -- Length (number)
  -- CharSet (string, optional); e.g. %l%d for lower case letters and digits

  CharSet = CharSet or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  if CharSet == "" then
    return ""
  else
    local Result = {}
    local Lookup = Built[CharSet] or AddLookup(CharSet)
    local Range = #Lookup

    for Loop = 1, Length do
      Result[Loop] = Lookup[math.random(1, Range)]
    end

    return table.concat(Result)
  end
end

local function slice(t, from, to)
  if from then
    if from < 1 then
      from = #t + from + 1
    end
  else
    from = 1
  end
  if to then
    if to < 1 then
      to = #t + to + 1
    end
  else
    to = #t
  end
  local r = {}
  for i = from, to do
    r[#r + 1] = t[i]
  end
  return r
end

local function folders(path, depth, level, ret)
  ret = ret or {}
  depth = depth or false
  level = level or 0
  for file in assert(lfs.dir(path)) do
    local p = path .. "/" .. file
    local t = lfs.attributes(p, "mode")
    if t == "file" then
    elseif t == "directory" and file ~= "." and file ~= ".." then
      ret[#ret + 1] = p
      if not depth or level < depth then
        folders(p, depth, level + 1, ret)
      end
    end
  end
  return ret
end

local function log(s)
  return ngx.log(ngx.ERR, s)
end

local READONLY_EMPTY_TABLE = setmetatable({}, {
  __newindex = function()
    error("this table is readonly")
  end
})
local function array_to_set(a)
  local d = {}
  for i, k in ipairs(a) do
    d[k] = true
  end
  return d
end

local function chunk(a, n)
  n = n or 1
  local res = array {}
  local unit = {}
  for _, e in ipairs(a) do
    if #unit == n then
      res[#res + 1] = unit
      unit = { e }
    else
      unit[#unit + 1] = e
    end
  end
  res[#res + 1] = unit
  return res
end

local function set(a)
  local s = {}
  for _, e in ipairs(a) do
    s[e] = true
  end
  return s
end

---@param a table
---@return array
local function values(a)
  local ret = array()
  for _, v in pairs(a) do
    ret[#ret + 1] = v
  end
  return ret
end

---@param t table
---@return array
local function keys(t)
  local ret = array()
  for k, _ in pairs(t) do
    ret[#ret + 1] = k
  end
  return ret
end

local object = {
  contains = function(self, a, b)
    for k, v in pairs(b) do
      if not self:same(a[k], v) then
        return false
      end
    end
    return true
  end,
  same = function(self, a, b)
    if type(a) ~= type(b) then
      return false
    end
    if type(a) == "table" then
      if #keys(a) == #keys(b) then
        return self:contains(a, b)
      else
        return false
      end
    else
      return a == b
    end
  end
}

local function combine(a, n)
  if #a == n then
    return { a }
  elseif n == 1 then
    return map(a, function(e)
      return { e }
    end)
  elseif #a > n then
    local head = a[1]
    local rest = slice(a, 2)
    return list(combine(rest, n), map(combine(rest, n - 1), function(e)
      return { head, unpack(e) }
    end))
  else
    return {}
  end
end

local function from_entries(a)
  local ret = {}
  for i, e in ipairs(a) do
    ret[e[1]] = e[2]
  end
  return ret
end

local function entries(a)
  local ret = array {}
  for k, v in pairs(a) do
    ret[#ret + 1] = { k, v }
  end
  return ret
end

local function load_json(fn)
  local file = assert(io.open(fn))
  local json = assert(file:read("a*"))
  file:close()
  return cjson_safe.decode(json)
end

local function valid_id(id)
  id = tonumber(id)
  if not id or id ~= math_floor(id) then
    return
  else
    return id
  end
end

local function eval(token, context)
  local f = assert(loadstring(string_format("return %s", token)))
  setfenv(f, dict(_G, context))
  return f()
end

local function assert_nil(...)
  if select(1, ...) == nil then
    error(select(2, ...))
  else
    return ...
  end
end

local function to_query_string(t)
  local res = {}
  for k, v in pairs(t) do
    res[#res + 1] = k .. "=" .. v
  end
  return table_concat(res, "&")
end

local localtime = ngx.localtime
local function get_age(sfzh, now)
  now = now or localtime()
  local month_diff = tonumber(now:sub(6, 7)) - tonumber(sfzh:sub(11, 12))
  local year_diff = tonumber(now:sub(1, 4)) - tonumber(sfzh:sub(7, 10))
  if month_diff < 0 then
    return year_diff - 1
  elseif month_diff == 0 then
    local day_diff = tonumber(now:sub(9, 10)) - tonumber(sfzh:sub(13, 14))
    if day_diff < 0 then
      return year_diff - 1
    else
      return year_diff
    end
  else
    return year_diff
  end
end

local function get_xb(sfzh)
  local n = tonumber(sfzh:sub(-2, -2)) or 1
  if n % 2 == 0 then
    return "女"
  else
    return "男"
  end
end

local INHERIT_METHODS = {
  new = true,
  __add = true,
  __sub = true,
  __mul = true,
  __div = true,
  __mod = true,
  __pow = true,
  __unm = true,
  __concat = true,
  __len = true,
  __eq = true,
  __lt = true,
  __le = true,
  __index = true,
  __newindex = true,
  __call = true,
  __tostring = true
}
local function class_new(cls, self)
  return setmetatable(self or {}, cls)
end

local function class__call(cls, attrs)
  local self = cls:new()
  self:init(attrs)
  return self
end

local function class__init(self, attrs)

end

---make a class with methods: __index, __call, class, new
---@param cls table
---@param parent? table
---@param copy_parent? boolean
---@return table
local function class(cls, parent, copy_parent)
  if parent then
    if copy_parent then
      for key, value in pairs(parent) do
        if cls[key] == nil then
          cls[key] = value
        end
      end
    end
    setmetatable(cls, parent)
    for method, _ in pairs(INHERIT_METHODS) do
      if cls[method] == nil and parent[method] ~= nil then
        cls[method] = parent[method]
      end
    end
  end
  function cls.class(cls, subcls, copy_parent)
    return class(subcls, cls, copy_parent)
  end

  cls.new = cls.new or class_new
  cls.init = cls.init or class__init
  cls.__call = cls.__call or class__call
  cls.__index = cls
  return cls
end

local function file_exists(name)
  local f = io.open(name, "r")
  if f ~= nil then
    io.close(f)
    return true
  else
    return false
  end
end

local function dir_exists(path)
  if (lfs.attributes(path, "mode") == "directory") then
    return true
  end
  return false
end

local function files(path, depth, level, ret)
  ret = ret or {}
  depth = depth or false
  level = level or 0
  if not dir_exists(path) then
    return ret
  end
  for file in lfs.dir(path) do
    local p = path .. '/' .. file
    local t = lfs.attributes(p, "mode")
    if t == "file" then
      ret[#ret + 1] = p
    elseif t == "directory" and file ~= '.' and file ~= '..' then
      if not depth or level < depth then
        files(p, depth, level + 1, ret)
      end
    end
  end
  return ret
end

---/a/b/c => {'a','b', 'c'}
---@param path string
---@return array
local function split_path(path)
  local res = array()
  for k in path:gmatch("([^/\\]+)") do
    table.insert(res, k)
  end
  return res
end

local function callable(f)
  return type(f) == "function" or (type(f) == "table" and getmetatable(f) and callable(getmetatable(f).__call))
end

local function get_dir(path)
  return path:match("^(.+)/[^/]+$")
end

local function get_filename(path)
  return path:match("^.+/(.+)$")
end

local function get_extension(path)
  return path:match("^.+(%..+)$")
end

local function mkdirs(path)
  local ppath = get_dir(path)
  if ppath and not dir_exists(ppath) then
    assert(mkdirs(ppath))
  end
  if not dir_exists(path) then
    return lfs.mkdir(path)
  end
  return true
end

local function split_filename_extension(path)
  return path:match("^(.+)(%..+)$")
end

local function require_cd(name)
  local cd = get_dir(debug.getinfo(2, "S").source:sub(2))
  local ok, mod = pcall(require, cd .. '/' .. name)
  if not ok then
    return require(name)
  else
    return mod
  end
end

local function sorted_encode(obj, indent)
  local t = type(obj)
  if t == 'table' then
    if repr.isArray(obj) then
      return string_format("[%s]", array(obj):map(function(e)
        return sorted_encode(e, false)
      end):join(','))
    else
      if indent == false then
        return string_format("{%s}", keys(obj):sort():map(function(key)
          return string_format([["%s":%s]], key, sorted_encode(obj[key], false))
        end):join(','))
      else
        indent = indent or "  "
        return string_format("{\n%s%s\n%s}", indent, keys(obj):sort():map(function(key)
          return string_format([["%s":%s]], key, sorted_encode(obj[key], indent .. '  '))
        end):join(',\n' .. indent), indent:sub(1, -3))
      end
    end
  else
    return repr.serializeNonTableValue(obj)
  end
end

local function write_json(fn, obj)
  local file, json, res, err
  file, err = io.open(fn, "w")
  if not file then
    return nil, err
  end
  json, err = sorted_encode(obj)
  if not json then
    return nil, err
  end
  res, err = file:write(json)
  if not res then
    return nil, err
  end
  return file:close()
end

local function loger_sql(sql)
  if sql:sub(-1) ~= ';' then
    sql = sql .. ';'
  end
  return writefile(sql, string.format("logs/%s.sql", os.date("%Y%m%d-%H-%M-%S", os.time())))
end

local function exec(cmd, ...)
  local f = assert(io.popen(string_format(cmd, ...)))
  local res = assert(f:read("*a"))
  f:close()
  return res
end

---comment
---@param s string
---@return string
local function camel_to_snake(s)
  return s:sub(1, 1):lower() .. (s:sub(2):gsub('([A-Z])', function(c)
    return '_' .. c:lower()
  end))
end

---@param s string
---@return string
local function snake_to_camel(s)
  return (s:gsub('(_[a-zA-Z])', function(c)
    return c:sub(2):upper()
  end))
end

local function to_camel_json(obj)
  if type(obj) == 'table' then
    local res = {}
    for key, value in pairs(obj) do
      if type(key) == 'string' then
        res[snake_to_camel(key)] = to_camel_json(value)
      else
        res[key] = to_camel_json(value)
      end
    end
    return res
  else
    return obj
  end
end

local function range(n)
  local res = array()
  for i = 1, n do
    res[i] = i
  end
  return res
end

local function cache_by_seconds2(f, cache_time)
  local ok, result, err, cache_gen_time;
  local function _cache()
    local now = ngx_time()
    if result == nil or (now - cache_gen_time > cache_time) then
      ok, result, err = pcall(f)
      if not ok then
        err = result
        result = nil
      end
      cache_gen_time = now
    end
    return result, err
  end
  return _cache
end

local function cache_by_db(f, cache_time)
  cache_time = time_parser(cache_time)
  if cache_time == 0 then
    return f
  end
  local key = 'cache_by_db:' .. tostring(f)
  -- local function set_value(result)
  --   return db:set(key, result, cache_time)
  -- end
  local function _cache(refresh)
    local ok, result, err
    result = db:get(key)
    if result == nil or refresh then
      ok, result, err = pcall(f)
      if not ok then
        return nil, result
      elseif result == nil then
        return nil, err
      else
        db:set(key, result, cache_time)
        return result
      end
    else
      return result
    end
  end
  return _cache
end

local function cache_by_key_and_time(f, cache_time)
  local results = {}
  local err, cache_gen_time;
  local function _cache(key)
    if results[key] == nil or (ngx_time() - cache_gen_time > cache_time) then
      results[key], err = f(key)
      cache_gen_time = ngx_time()
    end
    return results[key], err
  end
  return _cache
end

local function get_keys(rows)
  local columns = {}
  if rows[1] then
    local d = {}
    for _, row in ipairs(rows) do
      for k, _ in pairs(row) do
        if not d[k] then
          d[k] = true
          table_insert(columns, k)
        end
      end
    end
  else
    for k, _ in pairs(rows) do
      table_insert(columns, k)
    end
  end
  return columns
end
local function chaining_operator(obj, key)
  local res = obj
  for i, value in ipairs(split(key, '.')) do
    res = res[value]
    if type(res) ~= 'table' then
      return res
    end
  end
  return res
end
local searchable_db_types = {
  varchar = true,
  text = true,
  timestamp = true,
  date = true,
  time = true
}
local function get_list_search_condition(data, model)
  if not data or type(data.key) ~= 'table' or type(data.value) ~= 'table' or #data.key ~= #data.value then
    return {}
  end
  local condition = {}
  if model then
    for i = 1, #data.key do
      local name = data.key[i]
      local field = model.fields[name]
      if searchable_db_types[field.db_type] then
        if field.static_choice_validator and field.static_choice_validator(data.value[i]) ~= nil then
          condition[data.key[i]] = data.value[i]
        else
          condition[data.key[i] .. '__contains'] = data.value[i]
        end
      elseif field.db_type == 'integer' or field.db_type == 'float' then
        condition[data.key[i]] = tonumber(data.value[i])
      end
    end
  else
    for i = 1, #data.key do
      condition[data.key[i] .. '__contains'] = data.value[i]
    end
  end
  return condition
end
local function pg_datetime_to_timestamp(str)
  local pattern = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)(.+)"
  local year, month, day, hour, min, sec, tz_offset = str:match(pattern)
  local date_table = {
    year = tonumber(year),
    month = tonumber(month),
    day = tonumber(day),
    hour = tonumber(hour),
    min = tonumber(min),
    sec = tonumber(sec),
    isdst = false
  }
  local timestamp = os.time(date_table)
  return timestamp
end
local function capitalize(model_name)
  return model_name:sub(1, 1):upper() .. model_name:sub(2)
end

---@param s string
---@return string
local function to_model_name(s)
  local name = (s:gsub('(_[a-zA-Z])', function(c)
    return c:sub(2):upper()
  end))
  return capitalize(name)
end

local function to_timestamp(date_string)
  -- 解析日期和时间字符串
  local year, month, day, hour, min, sec = string.match(date_string, '(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)')

  -- 创建一个日期时间对象
  local datetime = os.time({ year = year, month = month, day = day, hour = hour, min = min, sec = sec })
  return datetime
end

---comments
---@param func function
---@param seconds number
---@param get_key? function
---@param is_json? boolean
---@return fun(...):string|number|boolean|table
local function function_rate_limit(func, seconds, get_key, is_json)
  local limit_func
  if type(get_key) == 'function' then
    function limit_func(...)
      local key = assert(get_key(...))
      local result, err = db:get(key)
      if result == nil then
        if err ~= nil then
          error(string_format('failed to get %s from shared dict: %s', key, err))
        end
        -- expired or not existed
        result, err = func(...)
        if result ~= nil then
          db:set(key, is_json and cjson.encode(result) or result, seconds)
          return result
        elseif err ~= nil then
          error(err)
        end
      else
        return is_json and cjson.decode(result) or result
      end
    end
  else
    function limit_func(...)
      local key = ...
      if key == nil then
        error("failed to get key")
      end
      local result, err = db:get(key)
      if result == nil then
        if err ~= nil then
          error(string_format('failed to get %s from shared dict: %s', key, err))
        end
        -- expired or not existed
        result, err = func(...)
        if result ~= nil then
          db:set(key, is_json and cjson.encode(result) or result, seconds)
          return result
        elseif err ~= nil then
          error(err)
        end
      else
        return is_json and cjson.decode(result) or result
      end
    end
  end
  return limit_func
end

return {
  utf8sub = utf8sub,
  cache_by_db = cache_by_db,
  db = db,
  function_rate_limit = function_rate_limit,
  to_timestamp = to_timestamp,
  sorted_encode = sorted_encode,
  to_model_name = to_model_name,
  capitalize = capitalize,
  pg_datetime_to_timestamp = pg_datetime_to_timestamp,
  get_list_search_condition = get_list_search_condition,
  chaining_operator = chaining_operator,
  get_keys = get_keys,
  loger_sql = loger_sql,
  cache_by_key_and_time = cache_by_key_and_time,
  cache_by_seconds = cache_by_db,
  pjson = prettycjson,
  range = range,
  to_camel_json = to_camel_json,
  snake_to_camel = snake_to_camel,
  camel_to_snake = camel_to_snake,
  exec = exec,
  getenv = getenv,
  loger = loger,
  write_json = write_json,
  split_filename_extension = split_filename_extension,
  get_extension = get_extension,
  get_filename = get_filename,
  get_dir = get_dir,
  dir_exists = dir_exists,
  mkdirs = mkdirs,
  file_exists = file_exists,
  callable = callable,
  split_path = split_path,
  class = class,
  get_xb = get_xb,
  get_age = get_age,
  NULL = NULL,
  keys = keys,
  to_query_string = to_query_string,
  require = require_cd,
  assert_nil = assert_nil,
  eval = eval,
  valid_id = valid_id,
  load_json = load_json,
  values = values,
  entries = entries,
  from_entries = from_entries,
  combine = combine,
  object = object,
  set = set,
  chunk = chunk,
  array_to_set = array_to_set,
  slice = slice,
  map = map,
  filter = filter,
  mapkv = mapkv,
  filterkv = filterkv,
  dict = dict,
  list = list,
  dict_has = dict_has,
  list_has = list_has,
  to_html_attrs = to_html_attrs,
  strip = strip,
  empty = empty,
  dict_update = dict_update,
  list_extend = list_extend,
  reversed_inherited_chain = reversed_inherited_chain,
  inherited_chain = inherited_chain,
  sorted = sorted,
  curry = curry,
  serialize_basetype = serialize_basetype,
  serialize_attrs = serialize_attrs,
  split = split,
  split_gen = split_gen,
  cache = cache,
  cache_by_key = cache_by_key,
  time_parser = time_parser,
  locals = locals,
  upvalues = upvalues,
  zfill = zfill,
  repr = repr,
  debugger = debugger,
  compose_funcs = compose_funcs,
  utf8len = utf8len,
  random_string = random_string,
  cache_by_time = cache_by_time,
  files = files,
  folders = folders,
  byte_size_parser = byte_size_parser,
  READONLY_EMPTY_TABLE = READONLY_EMPTY_TABLE,
  log = log,
  copy = copy,
  jcopy = jcopy,
  deepcopy = deepcopy,
  JSON_TYPE = JSON_TYPE,
  ensure_json = ensure_json,
  find = find,
}
