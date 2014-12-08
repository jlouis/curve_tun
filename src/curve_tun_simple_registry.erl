%%% @doc module curve_tun_simple_registry implements a simple memory-based registry
%%% @end
-module(curve_tun_simple_registry).
-behaviour(gen_server).

%% Lifetime API
-export([start_link/0]).

%% API
-export([]).

%% Callbacks
-export([init/1, code_change/3, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-record(state, {}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
    
%% Callbacks

%% @private
init([]) ->
    {ok, #state{}}.
    
%% @private
handle_cast(_M, State) ->
    {noreply, State}.
    
%% @private
handle_call(_M, _From, State) ->
    {reply, {error, bad_call}, State}.
    
%% @private
handle_info(_M, State) ->
    {noreply, State}.
    
%% @private
code_change(_OldVsn, State, _Aux) ->
    {ok, State}.
    
%% @private
terminate(_Reason, _State) ->
    ok.
