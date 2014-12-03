%%%-------------------------------------------------------------------
%% @doc gen_nacl top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(gen_nacl_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    Vaults = vault_providers(),
    {ok, { {one_for_all, 3, 3600}, Vaults ++ []} }.

%%====================================================================
%% Internal functions
%%====================================================================
vault_providers() ->
    {ok, Modules} = application:get_env(gen_nacl, vault_providers),
    vault_providers(Modules).
    
vault_providers([]) -> [];
vault_providers([M|Ms]) ->
    Child = {M, {M, start_link, []}, permanent, 5000, workers, [M]},
    [Child | vault_providers(Ms)].
