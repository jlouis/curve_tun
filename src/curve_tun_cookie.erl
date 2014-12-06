-module(curve_tun_cookie).
-behaviour(gen_server).

-export([start_link/0]).
-export([cookie_key/0]).

-export([init/1, code_change/3, terminate/2, handle_info/2, handle_cast/2, handle_call/3]).

-define(SERVER, ?MODULE).

-record(state, {
	key :: binary()
}).

%% API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

cookie_key() ->
    gen_server:call(?SERVER, cookie_key).

%% Callbacks
init([]) ->
    Key = minute_key(),
    erlang:send_after(60 * 1000, self(), recompute_key),
    {ok, #state{ key = Key}}.

handle_call(cookie_key, _From, #state { key = Key } = State) ->
    {reply, Key, State};
handle_call(_Msg, _From, State) ->
    {reply, {error, not_implemented}, State}.
    
handle_cast(Msg, State) ->
    error_logger:info_report([{wrong_handle_cast, Msg}]),
    {noreply, State}.
    
handle_info(Msg, State) ->
    error_logger:info_report([{wrong_handle_cast, Msg}]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Aux) ->
    {ok, State}.

%% Internal functions
minute_key() ->
    crypto:strong_rand_bytes(enacl:secretbox_key_size()).
