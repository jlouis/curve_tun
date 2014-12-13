%%% Test module
-module(t).

-export([l/0, a/1, c/0, r/0]).
-export([l_loop/0]). %% For reloading

-define(PUBKEY, <<81,13,101,52,29,109,136,196,86,91,34,91,3,19,150,3,215, 43,210,9,242,146,119,188,153,245,78,232,94,113,37,47>>).

l() ->
    Self = self(),
    Pid = spawn(fun() -> l_init(Self) end),
    receive
        {Pid, LSock} -> LSock
    end.

l_init(Parent) ->
    register(listener, self()),
    {ok, LSock} = curve_tun_connection:listen(6789),
    Parent ! LSock,
    l_loop().
    
l_loop() ->
    receive
        done -> ok
    after 5000 ->
        ?MODULE:l_loop()
    end.

a(LSock) ->
    curve_tun_connection:accept(LSock).
    
c() ->
    curve_tun_connection:connect({127,0,0,1}, 6789, [{key, ?PUBKEY}]).

r() ->
    curve_tun_simple_registry:register({127,0,0,1}, ?PUBKEY).
