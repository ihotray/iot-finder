local M = {}

--params: string, response from broadcaster
--return: string or none
M.on_message = function (params)
    -- do something with params
    return 'response from broadcaster:'..params
end


return M