-module(curve_tun_cookie).
-behaviour(gen_server).

-export([start_link/0]).
-export([current_key/0, recent_keys/0]).

-export([init/1, code_change/3, terminate/2, handle_info/2, handle_cast/2, handle_call/3]).

-define(SERVER, ?MODULE).
-define(ROTATE_PERIOD, 60 * 1000).

-record(state, {
	keys :: [binary()]
}).

%% API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

current_key() ->
    gen_server:call(?SERVER, current_key).

recent_keys() ->
    gen_server:call(?SERVER, recent_keys).

%% Callbacks
init([]) ->
    Key = minute_key(),
    erlang:send_after(?ROTATE_PERIOD, self(), recompute_key),
    {ok, #state{ keys = [Key] }}.

handle_call(current_key, _From, #state { keys = [K | _] } = State) ->
    {reply, K, State};
handle_call(recent_keys, _From, #state { keys = Keys } = State) ->
    {reply, Keys, State};
handle_call(_Msg, _From, State) ->
    {reply, {error, not_implemented}, State}.
    
handle_cast(Msg, State) ->
    error_logger:info_report([{wrong_handle_cast, Msg}]),
    {noreply, State}.
    
handle_info(recompute_key, #state { keys = [Existing | _ ] } = State) ->
    erlang:send_after(?ROTATE_PERIOD, self(), recompute_key),
    Key = minute_key(),
    {noreply, State#state{ keys = [Key, Existing] }};
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
