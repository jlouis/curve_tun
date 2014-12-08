%%% @doc module curve_tun_simple_registry implements a simple memory-based registry
%%% @end
-module(curve_tun_simple_registry).
-behaviour(gen_server).

%% Lifetime API
-export([start_link/0]).
-export([lookup/1, register/2, verify/2]).

%% API
-export([]).

%% Callbacks
-export([init/1, code_change/3, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-record(state, {
	dict :: dict:dict(inet:ip_addres(), binary())}).

%% API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register(IP, PubKey) ->
    gen_server:call(?SERVER, {register, IP, PubKey}).

lookup(IP) ->
    gen_server:call(?SERVER, {lookup, IP}).

verify(Socket, PubKey) ->
    {ok, {Address, _Port}} = inet:peername(Socket),
    case lookup(Address) of
        {ok, PubKey} -> true;
        {ok, _WrongKey} -> false;
        {error, not_found} -> false
    end.
        
%% Callbacks

%% @private
init([]) ->
    {ok, #state{ dict = dict:new() }}.
    
%% @private
handle_cast(_M, State) ->
    {noreply, State}.
    
%% @private
handle_call({register, IP, PubKey}, _From, #state { dict = Dict } = State) ->
    {reply, ok, State#state { dict = dict:store(IP, PubKey, Dict) }};
handle_call({lookup, IP}, _From, #state { dict = Dict } = State) ->
    Reply = lookup(IP, Dict),
    {reply, Reply, State};
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

lookup(IP, Dict) ->
    case dict:find(IP, Dict) of
        {ok, PubKey} -> {ok, PubKey};
        error -> {error, not_found}
    end.
