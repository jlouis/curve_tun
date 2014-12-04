-module(curve_tun_vault_dummy).

-behaviour(gen_server).
-define(SERVER, ?MODULE).

-export([start_link/0]).
-export([public_key/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
	public_key :: binary(),
	secret_key :: binary()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []). %% @todo mark the process as sensitive

public_key() ->
    gen_server:call(?SERVER, public_key).

init([]) ->
    #{ public := Public, secret := Secret } = enacl:box_keypair(),
    {ok, #state { public_key = Public, secret_key = Secret }}.

handle_call(public_key, _From, #state { public_key = PK } = State) ->
    {reply, PK, State}.

handle_cast(Msg, State) ->
    error_logger:info_msg("Unknown handle_cast message: ~p", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    error_logger:info_msg("Unknown handle_info message: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
    
code_change(_OldVsn, State, _Aux) ->
    {ok, State}.
