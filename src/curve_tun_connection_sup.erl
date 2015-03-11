-module(curve_tun_connection_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([start_child/1]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_child(Args) ->
    supervisor:start_child(?MODULE, Args).

init(_O) ->
    RestartStrategy = simple_one_for_one,
    MaxR = 50,
    MaxT = 3600,
    
    Name = undefined,
    StartFunc = {curve_tun_connection, start_link, []},
    Restart = temporary,
    Shutdown = 4000,
    Modules = [curve_tun_connection],
    Type = worker,
    
    ChildSpec = {Name, StartFunc, Restart, Shutdown, Type, Modules},
    {ok,
      {{RestartStrategy, MaxR, MaxT},
       [ChildSpec]}}.

