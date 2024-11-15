local M = {}

-- params: string, response from broadcaster
-- return: string or none
M.on_message = function(params)
    -- do something with params
    return 'response from broadcaster:' .. params
end

-- create a message to send to broadcaster
M.load_message = function()
    return '{"type": "discovery", "params": {"mac": "7C:27:3C:08:57:94"}}'
end

return M
