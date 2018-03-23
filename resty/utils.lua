local ENCODE_AS_ARRAY = require "cjson".empty_array_mt 
-- ** why require "cjson.safe".empty_array_mt not work
local type = type
local pairs = pairs
local next = next
local ipairs = ipairs
local table_sort = table.sort
local table_concat = table.concat
local table_insert = table.insert
local string_format = string.format
local ngx_re_gsub = ngx.re.gsub
local ngx_re_match = ngx.re.match
local ngx_time = ngx.time
local lfs
do
    local o, l = pcall(require, "syscall.lfs")
    if not o then o, l = pcall(require, "lfs") end
    if o then lfs = l end
end

local is_windows = package.config:sub(1,1) == '\\'

local function array(t)
    return setmetatable(t or {}, ENCODE_AS_ARRAY)
end
local function map(tbl, func)
    local res = {}
    for i=1, #tbl do
        res[i] = func(tbl[i])
    end
    return res
end
local function filter(tbl, func)
    local res = {}
    for i=1, #tbl do
        local v = tbl[i]
        if func(v) then
            res[#res+1] = v
        end
    end
    return res
end
local function list(a, b)
    local t = {}
    if a then
        for k, v in ipairs(a) do
            t[#t+1] = v
        end
    end
    if b then
        for k, v in ipairs(b) do
            t[#t+1] = v
        end
    end
    return t
end
local function list_extend(t, a)
    for i = 1, #a do
        t[#t+1] = a[i]
    end
    return t
end
local function list_has(t, e)
    for i, v in ipairs(t) do
        if v == e then
            return i
        end
    end
    return false
end
local function dict(a, b)
    local t = {}
    if a then
        for k, v in pairs(a) do
            t[k] = v
        end
    end
    if b then
        for k, v in pairs(b) do
            t[k] = v
        end
    end            
    return t
end
local function dict_update(t, a)
    if a then
        for k, v in pairs(a) do
            t[k] = v
        end
    end
    return t
end
local function dict_has(t, e)
    for k, v in pairs(t) do
        if v == e then
            return true
        end
    end
    return false
end
local function string_strip(value)
    return (ngx_re_gsub(value, [[^\s*(.+)\s*$]], '$1', 'jo'))
end
local function is_empty_value(value)
    if value == nil or value == '' then
        return true
    -- elseif type(value) == 'table' then
    --     return next(value) == nil
    else
        return false
    end
end
local function to_html_attrs(tbl)
    local attrs = {}
    local boolean_attrs = {}
    for k, v in pairs(tbl) do
        if v == true then
            boolean_attrs[#boolean_attrs+1] = ' '..k
        elseif v then -- exclude false
            -- ** 暂时忽略v包含双引号的情况
            -- 这里也看出, 如果v是数字, 从最终结果来看无论是2还是"2"都是等效的
            attrs[#attrs+1] = string_format(' %s="%s"', k, v)
        end
    end
    return table_concat(attrs, "")..table_concat(boolean_attrs, "")
end
local function reversed_inherited_chain(self)
    local res = {self}
    local cls = getmetatable(self)
    while cls do
        table.insert(res, 1, cls)
        self = cls
        cls = getmetatable(self)
    end
    return res
end
local function inherited_chain(self)
    local res = {self}
    local cls = getmetatable(self)
    while cls do
        res[#res+1] = cls
        self = cls
        cls = getmetatable(self)
    end
    return res
end
local function sorted(t, func)
    local keys = {}
    for k, v in pairs(t) do
        keys[#keys+1] = k
    end
    table_sort(keys, func)
    local i = 0
    return function ()
        i = i + 1
        local key = keys[i]
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
    if type(v) == 'string' then
        return '"'..v:gsub('\\', '\\\\'):gsub('"', '\\"')..'"'
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
            res[#res+1] = string_format('%s = %s', string_format('`%s`.`%s`', table_name, k), serialize_basetype(v))
        end
    else
        for k, v in pairs(attrs) do
            res[#res+1] = string_format('%s = %s', k, serialize_basetype(v))
        end
    end
    return table_concat(res, ", ")
end
local function split(s, sep)
    local i = 1
    local res = {}
    local a, b
    while true do
        a, b = s:find(sep, i, true)
        if a then
            res[#res+1] = s:sub(i, a - 1)
            i = b + 1
        else
            res[#res+1] = s:sub(i)
            break
        end
    end
    return res
end
local unit_table = {s=1, m=60, h=3600, d=3600*24, w=3600*24*7, M=3600*24*30, y=3600*24*365}
local function time_parser(t)
    if type(t) == 'string' then
        local unit = string.sub(t,-1,-1)
        local secs = unit_table[unit]
        assert(secs, 'invalid time unit: '..unit)
        local ts = string.sub(t, 1, -2)
        local num = tonumber(ts)
        assert(num, "can't convert `"..ts.."` to a number")    
        return num * secs
    elseif type(t) == 'number' then
        return t
    else
        return 0
    end
end
local size_table = {kb=1024, mb=1024*1024, gb=1024*1024*1024}
local function byte_size_parser(t)
    if type(t) == 'string' then
        local unit = string.sub(t,-2,-1):lower()
        local bytes = size_table[unit]
        assert(bytes, 'invalid size unit: '..unit)
        local ts = string.sub(t, 1, -3)
        local num = tonumber(ts)
        assert(num, "can't convert `"..ts.."` to a number")    
        return num * bytes
    elseif type(t) == 'number' then
        return t
    else
        return 0
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
    local cache_time = time_parser(cache_time)
    if cache_time == 0 then
        return f
    end
    local function _cache()
        if result == nil or ngx_time() - cache_gen_time > cache_time then
            result, err = f()
            cache_gen_time = ngx_time()
            -- loger('not read from cache')
        else
            -- loger('read from cache')
        end
        return result, err
    end
    return _cache
end


local get_dirs
if is_windows then
    function get_dirs(directory)
        local t, popen = {}, io.popen
        local pfile = popen('dir "'..directory..'" /b /ad')
        for filename in pfile:lines() do
            if not filename:find('__') then
                t[#t+1] = filename
            end
        end
        pfile:close()
        return t
    end
else
    function get_dirs(directory)
        local t = {}
        local pfile = io.popen('ls -l "'..directory..'" | grep ^d')
        for filename in pfile:lines() do
            t[#t+1] = filename:match('%d%d:%d%d (.+)$')
        end
        pfile:close()
        return t
    end
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
    c = c or ' '
    for i=1,n-len do
        s = s..c
    end
    return s
end
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local MAX_DEPTH = 2
local MAX_LENGTH = 10
local function add_right_space(num)
    local res = ''
    for i=1, num or 1 do
        res = res..' '
    end
    return res
end

local function simple(k)
    if type(k) == 'string' then 
        -- **
        k = k:gsub('"', '\\"')
        k = k:gsub('\n', '\\n')
        k = k:gsub('\r', '\\r')
        k = k:gsub('\t', '\\t')
        return  '"'..k..'"'
    elseif type(k) == 'number' then 
        return tostring(k)
    else -- nil, true, false
        return '"'..tostring(k)..'"'
    end
end   
local function raw_tostring(obj)
    if type(obj) == 'table' then
        local mt = getmetatable(obj)
        setmetatable(obj, nil)
        local res = tostring(obj)
        setmetatable(obj, mt)
        return res
    else
        return tostring(obj)
    end
end
local function _repr(obj, max_depth, ind, deep, already)
    local label = type(obj)
    if label == 'table' then
        local res = {}
        local normalize = {}
        local indent = '  '..ind
        local table_key = raw_tostring(obj)
        local max_key_len = 0
        for k,v in pairs(obj) do
            k = simple(k)
            local k_len = string.len(k)
            if k_len>max_key_len then
                max_key_len = k_len
            end
        end
        if max_key_len>MAX_LENGTH then
            max_key_len = MAX_LENGTH
        end
        if table_key ~= nil then -- todo why this is needed
            already[table_key] = table_key
        end
        for k,v in pairs(obj) do
            k = simple(k)
            if type(v) == 'table' then
                local key = raw_tostring(v)
                if next(v) == nil then
                    v = '{}'
                elseif already[key] then
                    v = simple(key)
                elseif deep > max_depth then
                    v = simple('*exceed max deepth*')
                else
                    v = '{\\\\'..(raw_tostring(v) or '').._repr(v, max_depth, indent..add_right_space(max_key_len+3), deep+1, already)
                end
            else
                v = simple(v)
            end
            normalize[k] = v --string.format('\n%s%s: %s,', indent, k, v)
        end 
        for k, v in sorted(normalize) do
            res[#res+1] = string.format('\n%s%s: %s,', indent, zfill(k, max_key_len), v)
        end
        return table.concat(res)..'\n'..add_right_space(string.len(indent)-2)..'}'         
    else
        return simple(obj)
    end
end

local function repr(obj, max_depth)
    max_depth = max_depth or MAX_DEPTH
    if type(obj)  == 'table' then
        return '{\\\\'..raw_tostring(obj).._repr(obj, max_depth, '', 1, {})
    else
        return simple(obj)
    end
end
local function loger(...)
    local delimiter = '***************************'
    local res = {}
    for i,v in ipairs({...}) do
        res[i] = repr(v)
    end
    ngx_log(ngx_ERR,string.format('\n%s\n%s\n%s', delimiter, table.concat(res, " "), delimiter))
end
local function debugger(e) 
    return debug.traceback()..e 
end

local ok, cjson = pcall(require, "cjson.safe")
local enc = ok and cjson.encode or function() return nil, "Lua cJSON encoder not found" end
local cat = table.concat
local sub = string.sub
local rep = string.rep
local function pjson(dt, lf, id, ac, ec)
    local s, e = (ec or enc)(dt)
    if not s then return s, e end
    lf, id, ac = lf or "\n", id or "\t", ac or " "
    local i, j, k, n, r, p, q  = 1, 0, 0, #s, {}, nil, nil
    local al = sub(ac, -1) == "\n"
    for x = 1, n do
        local c = sub(s, x, x)
        if not q and (c == "{" or c == "[") then
            r[i] = p == ":" and cat{ c, lf } or cat{ rep(id, j), c, lf }
            j = j + 1
        elseif not q and (c == "}" or c == "]") then
            j = j - 1
            if p == "{" or p == "[" then
                i = i - 1
                r[i] = cat{ rep(id, j), p, c }
            else
                r[i] = cat{ lf, rep(id, j), c }
            end
        elseif not q and c == "," then
            r[i] = cat{ c, lf }
            k = -1
        elseif not q and c == ":" then
            r[i] = cat{ c, ac }
            if al then
                i = i + 1
                r[i] = rep(id, j)
            end
        else
            if c == '"' and p ~= "\\" then
                q = not q and true or nil
            end
            if j ~= k then
                r[i] = rep(id, j)
                i, k = i + 1, j
            end
            r[i] = c
        end
        p, i = c, i + 1
    end
    return cat(r)
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
    local _, cnt = s:gsub('[^\128-\193]',"")
    return cnt
end

local Chars = {}
for Loop = 0, 255 do
   Chars[Loop+1] = string.char(Loop)
end
local String = table.concat(Chars)

local Built = {['.'] = Chars}

local AddLookup = function(CharSet)
   local Substitute = string.gsub(String, '[^'..CharSet..']', '')
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

   local CharSet = CharSet or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

   if CharSet == '' then
      return ''
   else
      local Result = {}
      local Lookup = Built[CharSet] or AddLookup(CharSet)
      local Range = #Lookup

      for Loop = 1,Length do
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
    for i=from, to do
        r[#r+1] = t[i]
    end
    return r
end

local function callable(f)
    return type(f) == 'function' or (
        type(f) == 'table' 
        and getmetatable(f) 
        and getmetatable(f).__call)
end

local function files(path, depth, level, ret)
    ret = ret or {}
    depth = depth or false
    level = level or 0
    for file in lfs.dir(path) do
        local p = path..'/'..file
        local t = lfs.attributes(p, "mode")
        if t == "file" then 
            ret[#ret+1] = p
        elseif t == "directory" and file ~= '.' and file ~= '..' then 
            if not depth or level < depth then
                files(p, depth, level+1, ret)
            end
        end
    end
    return ret
end
local function folders(path, depth, level, ret)
    ret = ret or {}
    depth = depth or false
    level = level or 0
    for file in lfs.dir(path) do
        local p = path..'/'..file
        local t = lfs.attributes(p, "mode")
        if t == "file" then 
            
        elseif t == "directory" and file ~= '.' and file ~= '..' then 
            ret[#ret+1] = p
            if not depth or level < depth then
                folders(p, depth, level+1, ret)
            end
        end
    end
    return ret
end
local function log(s)
    return ngx.log(ngx.ERR, s)
end

local READONLY_TABLE = setmetatable({}, 
    {__newindex=function(t, k, v) error('this table is readonly') end})

function deepcopy(orig)
    local already = {}
    local function f(orig)
        local orig_type = type(orig)
        local copy
        if orig_type == 'table' then
            if already[orig] then
                return orig
            end
            copy = {}
            for orig_key, orig_value in next, orig, nil do
                copy[f(orig_key)] = f(orig_value)
            end
            setmetatable(copy, f(getmetatable(orig)))
            already[copy] = true
        else -- number, string, boolean, etc
            copy = orig
        end
        return copy    
    end
    return f(orig)
end

return {
    copy = deepcopy,
    slice = slice,
    array = array,
    map = map, 
    filter = filter,
    dict = dict, 
    list = list, 
    dict_has = dict_has,
    list_has = list_has,
    to_html_attrs = to_html_attrs, 
    string_strip = string_strip, 
    is_empty_value = is_empty_value, 
    dict_update = dict_update, 
    list_extend = list_extend, 
    reversed_inherited_chain = reversed_inherited_chain, 
    inherited_chain = inherited_chain, 
    sorted = sorted, 
    curry = curry, 
    serialize_basetype = serialize_basetype, 
    serialize_attrs = serialize_attrs, 
    split = split, 
    cache = cache,
    cache_by_key = cache_by_key,
    time_parser = time_parser,
    get_dirs = get_dirs,
    locals = locals,
    upvalues = upvalues,
    zfill = zfill,
    repr = repr,
    loger = loger,
    debugger = debugger,
    pjson = pjson,
    compose_funcs = compose_funcs,
    utf8len = utf8len,
    serialize = serialize,
    random_string = random_string,
    callable = callable,
    cache_by_time = cache_by_time,
    files = files,
    folders = folders,
    byte_size_parser = byte_size_parser,
    READONLY_TABLE = READONLY_TABLE,
    log = log,
}