-module(curve_tun).

-export([connect/3, accept/1, listen/2, send/2, close/1, recv/1, controlling_process/2]).

connect(Host, Port, Opts) ->
    curve_tun_connection:connect(Host, Port, Opts).
    
accept(LSock) ->
    curve_tun_connection:accept(LSock).
    
listen(Port, Opts) ->
    curve_tun_connection:listen(Port, Opts).
    
send(Sock, Msg) ->
    curve_tun_connection:send(Sock, Msg).
    
close(Sock) ->
    curve_tun_connection:close(Sock).
    
recv(Sock) ->
    curve_tun_connection:recv(Sock).
    
controlling_process(Sock, Pid) ->
    curve_tun_connection:controlling_process(Sock, Pid).
