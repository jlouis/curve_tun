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
    #{ public := Public, secret := Secret } = keypair(),
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

%% For now, we always use the same keypair in the dummy vault.
keypair() ->
    #{
      public => <<81,13,101,52,29,109,136,196,86,91,34,91,3,19,150,3,215,
    		43,210,9,242,146,119,188,153,245,78,232,94,113,37,47>>,
      secret => <<79,5,69,119,45,58,176,227,13,41,218,168,234,190,227,142,
		160,217,229,207,248,33,10,84,184,133,218,238,93,40,44, 157>>
    }.
    