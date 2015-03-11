-module(curve_tun_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([suite/0, all/0, groups/0,
	 init_per_group/2, end_per_group/2,
	 init_per_suite/1, end_per_suite/1,
	 init_per_testcase/2, end_per_testcase/2]).

-export([suite_test/1]).

suite() ->
    [{timetrap, {seconds, 10}}].
    
%% Setup/Teardown
%% ----------------------------------------------------------------------
init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_suite(Config) ->
    error_logger:tty(false), %% Disable the error loggers tty output for tests
    {ok, Apps} = application:ensure_all_started(curve_tun),
    [{apps, Apps} | Config].

end_per_suite(Config) ->
    Apps = proplists:get_value(apps, Config),
    [ok = application:stop(A) || A <- Apps],
    ok.

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

%% Tests
%% ----------------------------------------------------------------------
groups() ->
    [{basic, [shuffle], [
        suite_test
    ]}].

all() ->
    [{group, basic}].

suite_test(_Config) ->
    ct:log("Running test suite for curve_tun"),
    ok.
