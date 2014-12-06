-module(curve_tun_connection).
-behaviour(gen_fsm).

-export([connect/3]).

%% Private callbacks
-export([start_link/0]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	ready/2, ready/3,
	initiating/2, initiating/3
]).

-record(curve_tun_socket, { pid :: pid() }).
-record(state, {}).

connect(Address, Port, Options) ->
    {ok, Pid} = start_link(),
    case gen_fsm:sync_send_event(Pid, {connect, Address, Port, Options}) of
        ok ->
            {ok, #curve_tun_socket { pid = Pid }};
        {error, Reason} ->
            {error, Reason}
    end.


%% @private
start_link() ->
    gen_fsm:start_link(?MODULE, [], []).
    
%% @private
init([]) ->
    {ok, ready, ready}.


%% @private
ready({connect, Address, Port, Options}, From, ready) ->
    TcpOpts = [{packet, 2} | Options],
    ServerKey = proplists:get_value(key, Options),
    case gen_tcp:connect(Address, Port, TcpOpts) of
        {error, Reason} ->
            {stop, normal, {error, Reason}, ready, ready};
        {ok, Socket} ->
            #{ public := EC, secret := ECs } = enacl:box_keypair(),
            case send_hello(Socket, ServerKey, EC, ECs) of
                ok ->
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, initiating, #{
                    	from => From,
                    	socket => Socket,
                    	public_key => EC,
                    	secret_key => ECs,
                    	peer_public_key => ServerKey }};
                {error, Reason} ->
                    {stop, normal, {error, Reason}, ready, ready}
            end
    end.
    
ready(_Msg, ready) ->
    {stop, argh, ready}.

initiating(_Msg, _From, _State) ->
    {stop, argh, ready}.

initiating(_Msg, _) ->
    {stop, argh, ready}.

handle_sync_event(Event, _From, Statename, State) ->
    error_logger:info_msg("Unknown sync_event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_event(Event, Statename, State) ->
    error_logger:info_msg("Unknown event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_info({tcp, S, Data}, Statename, #{ socket := S } = State) ->
    handle_packet(Data, Statename, State);
handle_info({tcp_closed, S}, Statename, # { socket := S } = State) ->
    handle_tcp_closed(Statename, State);
handle_info(Info, Statename, State) ->
    error_logger:info_msg("Unknown info msg ~p in state ~p", [Info, Statename]),
    {next_state, Statename, State}.

terminate(_Reason, _Statename, _State) ->
    ok.

code_change(_OldVsn, Statename, State, _Aux) ->
    {ok, Statename, State}.

%% Internal handlers
handle_packet(<<108,9,175,178,138,169,250,252, Pubkey:32/binary, Box/binary>>, accepting, State) ->
	todo;
handle_packet(<<28,69,220,185,65,192,227,246, N:16/binary, Box/binary>>, initiating,
	#{ public_key := EC, secret_key := ECs, peer_public_key := S } = State) ->
    Nonce = <<"CurveCPK", N/binary>>,
    {ok, <<ES:32/binary, K/binary>>} = enacl:box_open(Box, Nonce, S, ECs),
    todo.

handle_tcp_closed(_Statename, _State) ->
	todo.

%% Internal functions

%% Nonce generation
%% Short term nonces
st_nonce(hello, client, N) -> <<"CurveCP-client-H", N:64/integer-little>>;
st_nonce(initiate, client, N) -> <<"CurveCP-client-I", N:64/integer-little>>;
st_nonce(msg, client, N) -> <<"CurveCP-client-M", N:64/integer-little>>;
st_nonce(hello, server, N) -> <<"CurveCP-server-H", N:64/integer-little>>;
st_nonce(initiate, server, N) -> <<"CurveCP-server-I", N:64/integer-little>>;
st_nonce(msg, server, N) -> <<"CurveCP-server-M", N:64/integer-little>>.

send_hello(Socket, S, EC, ECs) ->
    N = 0,
    Box = enacl:box(binary:copy(<<0>>, 64), st_nonce(hello, client, N), S, ECs),
    H = <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer-little, Box/binary>>,
    gen_tcp:send(Socket, H).
    