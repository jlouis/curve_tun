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
-define(CHILD(I), {I, {I, start_link, []}, permanent, 5000, worker, [I]}).
-define(CHILDW(I, W), {I, {I, start_link, []}, permanent, W, worker, [I]}).

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
    CookieSpec = ?CHILDW(curve_tun_cookie, 2000),
    Vaults = vault_providers(),
    {ok, { {one_for_all, 3, 3600}, [CookieSpec] ++ Vaults ++ []} }.

%%====================================================================
%% Internal functions
%%====================================================================
vault_providers() ->
    {ok, Modules} = application:get_env(curve_tun, vault_providers),
    vault_providers(Modules).
    
vault_providers([]) -> [];
vault_providers([M|Ms]) ->
    Child = {M, {M, start_link, []}, permanent, 5000, worker, [M]},
    [Child | vault_providers(Ms)].
