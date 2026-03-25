local ffi = require 'ffi'
local bit = require 'bit'

ffi.cdef[[
    typedef struct { } i_net_channel_info;
    typedef struct { } c_net_message;
    typedef bool(__fastcall *send_net_msg_t)(i_net_channel_info*, void*, c_net_message*, bool, bool);

    typedef struct {
        uint8_t pad[0x58];
    } cclc_msg_voice_data_t;

    typedef struct {
        char pad_0000[0x9C];
        void* m_net_channel;
        uint32_t m_challenge_nr;
        char pad_00A4[0x64];
        uint32_t m_signon_state;
    } i_client_state;

    /* std::string in MSVC x86 ( 24 bytes )  */
    typedef struct {
        union {
            char buf[16];
            char* ptr;
        } data;
        uint32_t size;
        uint32_t capacity;
    } msvc_string;

    typedef struct {
        char pad_0000[8];
        int client;
        int audible_mask;
        uint32_t xuid_low;
        uint32_t xuid_high;
        msvc_string* voice_data;
        int proximity;
        bool caster;
        int format;
        int sequence_bytes;
        uint32_t section_number;
        uint32_t uncompressed_sample_offset;
    } c_svc_msg_voice_data;
]]

local function find_sig(module, pattern, offset)
    local sig = client.find_signature(module, pattern)
    if sig then return ffi.cast('uintptr_t', sig) + (offset or 0) end
    return nil
end

local function to_absolute(ptr)
    local addr = ffi.cast('char*', ptr)
    local rel = ffi.cast('int32_t*', addr + 1)[0]
    return ffi.cast('char*', addr + 5 + rel)
end

local client_state = ffi.cast('i_client_state***', find_sig('engine.dll', '\xA1\xCC\xCC\xCC\xCC\x8B\x80\xCC\xCC\xCC\xCC\xC3', 1) or error('clientstate'))[0][0]
local send_net_msg_fn = ffi.cast('send_net_msg_t', find_sig('engine.dll', '\x55\x8B\xEC\x83\xEC\x08\x56\x8B\xF1\x8B\x4D\x04') or error('sendnetmsg'))
local voice_init_fn = ffi.cast('void*(__thiscall*)(void*)', to_absolute( find_sig('engine.dll', '\xE8\xCC\xCC\xCC\xCC\x56\x8D\x84\x24\xCC\xCC\xCC\xCC\x50\x8D\x4C\x24\x28') or error('voice_init')))
local voice_set_fn = ffi.cast('void*(__thiscall*)(void*, void*, size_t)', to_absolute( find_sig('engine.dll', '\xE8\xCC\xCC\xCC\xCC\x83\x4C\x24\xCC\xCC\x83\x7C\x24') or error('voice_set')))

local coord_integer_bits = 14
local coord_fractional_bits = 5
local coord_denominator = bit.lshift(1, coord_fractional_bits)
local coord_resolution = 1.0 / coord_denominator

local net_buffer = {}
net_buffer.__index = net_buffer

function net_buffer.new()
    local self = setmetatable({}, net_buffer)
    self._data = ffi.new('uint8_t[4096]')
    self._cur_bit = 0
    self._read_bit = 0
    self._data_bits = 0
    self._overflow = false
    ffi.fill(self._data, 4096, 0)
    return self
end

function net_buffer.from_data(ptr, size)
    local self = setmetatable({}, net_buffer)
    self._data = ffi.new('uint8_t[4096]')
    ffi.copy(self._data, ptr, math.min(size, 4096))
    self._cur_bit = 0
    self._read_bit = 0
    self._data_bits = size * 8
    self._overflow = false
    return self
end

function net_buffer:write_bits(val, num_bits)
    val = bit.band(val, 0xFFFFFFFF)
    for i = 0, num_bits - 1 do
        if self._cur_bit >= 4096 * 8 then self._overflow = true; return self end
        local byte_idx = bit.rshift(self._cur_bit, 3)
        local bit_idx  = bit.band(self._cur_bit, 7)
        if bit.band(bit.rshift(val, i), 1) ~= 0 then
            self._data[byte_idx] = bit.bor(self._data[byte_idx], bit.lshift(1, bit_idx))
        end
        self._cur_bit = self._cur_bit + 1
    end
    return self
end

function net_buffer:write_coord(f_val)
    local abs_val = math.abs(f_val)
    local int_val = math.floor(abs_val)
    local fract_val = bit.band(math.floor(abs_val * coord_denominator), coord_denominator - 1)
    
    self:write_bits(int_val ~= 0 and 1 or 0, 1)
    self:write_bits(fract_val ~= 0 and 1 or 0, 1)
    
    if int_val ~= 0 or fract_val ~= 0 then
        self:write_bits(f_val < 0 and 1 or 0, 1)
        if int_val   ~= 0 then self:write_bits(int_val - 1, coord_integer_bits) end
        if fract_val ~= 0 then self:write_bits(fract_val, coord_fractional_bits) end
    end
    
    return self
end

function net_buffer:write_string(str)
    if type(str) ~= 'string' then
        str = tostring(str or '')
    end

    for i = 1, #str do
        self:write_bits(string.byte(str, i), 8)
    end

    self:write_bits(0, 8)
    
    return self
end

function net_buffer:read_bits(num_bits)
    local result = 0
    for i = 0, num_bits - 1 do
        if self._read_bit >= self._data_bits then self._overflow = true; return result end
        local byte_idx = bit.rshift(self._read_bit, 3)
        local bit_idx  = bit.band(self._read_bit, 7)
        result = bit.bor(result, bit.lshift(bit.band(bit.rshift(self._data[byte_idx], bit_idx), 1), i))
        self._read_bit = self._read_bit + 1
    end
    return result
end

function net_buffer:read_coord()
    local int_flag   = self:read_bits(1)
    local fract_flag = self:read_bits(1)
    
    if int_flag == 0 and fract_flag == 0 then return 0.0 end
    
    local sign_bit = self:read_bits(1)
    local int_val = int_flag ~= 0 and self:read_bits(coord_integer_bits) + 1 or 0
    local fract_val = fract_flag ~= 0 and self:read_bits(coord_fractional_bits) or 0
    local value = int_val + fract_val * coord_resolution
    
    return sign_bit ~= 0 and -value or value
end

function net_buffer:read_string()
    local chars = {}

    while not self:is_overflow() do
        local char_byte = self:read_bits(8)
        
        if char_byte == 0 or self:is_overflow() then
            break
        end
        
        table.insert(chars, string.char(char_byte))
    end
    
    return table.concat(chars)
end

function net_buffer:crypt(key)
    if not key or key == '' then return self end
    local key_len = string.len(key)
    local size = (self._cur_bit > 0) and bit.rshift(self._cur_bit + 7, 3) or bit.rshift(self._data_bits + 7, 3)
    
    for i = 0, size - 1 do
        local key_byte = string.byte(key, (i % key_len) + 1)
        self._data[i] = bit.bxor(self._data[i], key_byte)
    end
    
    return self
end

function net_buffer:reset()
    self._read_bit  = 0
    if self._cur_bit > 0 then self._data_bits = self._cur_bit end
    return self
end

function net_buffer:bytes_written() return bit.rshift(self._cur_bit + 7, 3) end
function net_buffer:is_overflow() return self._overflow end

-- https://github.com/Freaut/Detour-Hooking-Library
local detour = { hooks = {} }

local jmp_ecx               = find_sig('engine.dll', '\xFF\xE1')
local get_proc_addr         = ffi.cast('uint32_t**', find_sig('engine.dll', '\xFF\x15\xCC\xCC\xCC\xCC\xA3\xCC\xCC\xCC\xCC\xEB\x05', 2))[0][0]
local fn_get_proc_addr      = ffi.cast('uint32_t(__fastcall*)(unsigned int, unsigned int, uint32_t, const char*)', jmp_ecx)
local get_module_handle     = ffi.cast('uint32_t**', find_sig('engine.dll', '\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x74\x0B', 2))[0][0]
local fn_get_module_handle  = ffi.cast('uint32_t(__fastcall*)(unsigned int, unsigned int, const char*)', jmp_ecx)

local function proc_bind(module_name, function_name, typedef)
    local module_handle = fn_get_module_handle(get_module_handle, 0, module_name)
    local proc_address = fn_get_proc_addr(get_proc_addr, 0, module_handle, function_name)
    local call_fn = ffi.cast(ffi.typeof(typedef), jmp_ecx)
    return function(...) return call_fn(proc_address, 0, ...) end
end

local native_virtual_protect = proc_bind('kernel32.dll', 'VirtualProtect', 'int(__fastcall*)(unsigned int, unsigned int, void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect)')
local function virtual_protect(lp_address, dw_size, fl_new_protect, lp_fl_old_protect)
    return native_virtual_protect(ffi.cast('void*', lp_address), dw_size, fl_new_protect, lp_fl_old_protect)
end

function detour.new(typedef, callback, hook_address, size)
    size = size or 5
    local hook, mt = {}, {}
    local old_protect = ffi.new('unsigned long[1]')
    local original_bytes = ffi.new('uint8_t[?]', size)
    ffi.copy(original_bytes, ffi.cast('void*', hook_address), size)
    
    local c_callback = ffi.cast(typedef, callback)
    hook.cb_ref = c_callback
    local detour_address = tonumber(ffi.cast('intptr_t', ffi.cast('void*', c_callback)))

    hook.call = ffi.cast(typedef, hook_address)
    mt = {
        __call = function(self, ...)
            self.stop()
            local res = self.call(...)
            self.start()
            return res
        end
    }

    local hook_bytes = ffi.new('uint8_t[?]', size, 0x90)
    hook_bytes[0] = 0xE9
    ffi.cast('int32_t*', hook_bytes + 1)[0] = (detour_address - hook_address - 5)
    hook.status = false

    local function set_status(bool)
        hook.status = bool
        virtual_protect(hook_address, size, 0x40, old_protect)
        ffi.copy(ffi.cast('void*', hook_address), bool and hook_bytes or original_bytes, size)
        virtual_protect(hook_address, size, old_protect[0], old_protect)
    end

    hook.stop = function() set_status(false) end
    hook.start = function() set_status(true) end
    hook.start()
    
    table.insert(detour.hooks, hook)
    return setmetatable(hook, mt)
end

function detour.unhook_all()
    for _, hook in pairs(detour.hooks) do hook.stop() end
end
client.set_event_callback('shutdown', detour.unhook_all)

local receive_callbacks = {}

local function get_string_data(msvc_str)
    if msvc_str == nil or ffi.cast('void*', msvc_str) == nil then return nil, 0 end
    local size = msvc_str.size
    if size == 0 then return nil, 0 end
    return (msvc_str.capacity < 16) and msvc_str.data.buf or msvc_str.data.ptr, size
end

local svc_msg_voice_data_raw = find_sig('engine.dll', '\x55\x8B\xEC\x83\xE4\xF8\xA1\xCC\xCC\xCC\xCC\x81\xEC\xCC\xCC\xCC\xCC\x53\x56\x8B\xF1\xB9\xCC\xCC\xCC\xCC\x57\xFF\x50\x34\x8B\x7D\x08\x85\xC0\x74\x13\x8B\x47\x08\x40\x50')
local original_svc_msg_voice_data
local function hook_svc_msg_voice_data(state, edx, msg)
    if msg ~= nil and msg.voice_data ~= nil and #receive_callbacks > 0 then
        local ptr, size = get_string_data(msg.voice_data)
        if ptr ~= nil and size > 0 then
            local buf = net_buffer.from_data(ptr, size)
            for i = 1, #receive_callbacks do
                buf:reset()
                receive_callbacks[i](buf, msg)
            end
        end
    end
    return original_svc_msg_voice_data(state, edx, msg)
end

if svc_msg_voice_data_raw then
    original_svc_msg_voice_data = detour.new('bool(__fastcall*)(void*, void*, c_svc_msg_voice_data*)', hook_svc_msg_voice_data, svc_msg_voice_data_raw)
else
    error('svc_msg_voicedata: invalid signature')
end

local voice_message = {}
local registered_events = {}

local function send_raw(buf)
    if buf:is_overflow() then return false end
    
    local ptr = ffi.new('cclc_msg_voice_data_t')
    ffi.fill(ptr, ffi.sizeof('cclc_msg_voice_data_t'), 0)
    voice_init_fn(ptr)
    
    local base = ffi.cast('uintptr_t', ffi.cast('void*', ptr))
    ffi.cast('uint32_t*', base + 0x34)[0] = 63 -- has_bits
    ffi.cast('int32_t*',  base + 0x20)[0] = 0 -- format
    
    voice_set_fn(ffi.cast('void*', base + 0x8), buf._data, buf:bytes_written())
    send_net_msg_fn( ffi.cast('i_net_channel_info*', client_state[0].m_net_channel), ffi.cast('void*', 0), ffi.cast('c_net_message*', ptr), false, true )
    
    return true
end

function voice_message.send(event_or_callback, callback)
    if type(event_or_callback) == 'function' then
        local buf = net_buffer.new()
        event_or_callback(buf)
        return send_raw(buf)
    end

    local event = event_or_callback
    if registered_events[event] then
        client.unset_event_callback(event, registered_events[event])
    end

    registered_events[event] = function(...)
        local buf = net_buffer.new()
        callback(buf, ...)
        send_raw(buf)
    end
    
    client.set_event_callback(event, registered_events[event])

    return function()
        if registered_events[event] then
            client.unset_event_callback(event, registered_events[event])
            registered_events[event] = nil
        end
    end
end

function voice_message.buffer()
    return net_buffer.new()
end

function voice_message.stop(event)
    if registered_events[event] then
        client.unset_event_callback(event, registered_events[event])
        registered_events[event] = nil
    end
end

setmetatable(voice_message, {
    __call = function(self, callback)
        table.insert(receive_callbacks, callback)
        return function()
            for i, cb in ipairs(receive_callbacks) do
                if cb == callback then
                    table.remove(receive_callbacks, i)
                    break
                end
            end
        end
    end
})

return voice_message
