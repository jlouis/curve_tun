%%%-------------------------------------------------------------------
%% @doc curve_tun top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(curve_tun_sup).

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
    Cookie = {cookie, {curve_tun_cookie, start_link, []}, permanent, 2000, worker, [curve_tun_cookie]},

    {ok, Modules} = application:get_env(curve_tun, vault_providers),
    vault_providers([Cookie] ++ Modules).
    
vault_providers([]) -> [];
vault_providers([M|Ms]) ->
    Child = {M, {M, start_link, []}, permanent, 5000, worker, [M]},
    [Child | vault_providers(Ms)].
