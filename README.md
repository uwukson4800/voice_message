  ```lua
local voice_message = require 'voice_message'

voice_message.send( 'net_update_end', function( buffer )
    buffer:write_bits( 0xBEEF, 32 )
    buffer:write_bits( globals.servertickcount( ), 16 )
    buffer:crypt( 'yougame.biz' )
end )

-- Note that you wont be able to receive your own voice packet
-- unless voice_loopback convar is set to 1
voice_message( function( buffer, msg )
    local encrypted_pct = buffer:read_bits( 32 )
    buffer:reset()

    buffer:crypt( 'yougame.biz' )

    local pct = buffer:read_bits( 32 )
    if pct == 0xBEEF then
        local tickcount = buffer:read_bits( 16 )
        local sender_index = msg.client + 1

        local text = string.format( 'entity: %s [%d] | encrypted: 0x%X | decrypted: 0x%X | tickcount: %s', entity.get_player_name( sender_index ), sender_index, encrypted_pct, pct, tickcount )
        print( text )
    end
end )

-- [gamesense] entity: uwukson4800 [1] | encrypted: 0x6775D196 | decrypted: 0xBEEF | tickcount: 16085
  ```
