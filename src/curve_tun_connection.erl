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

    case gen_tcp:connect(Address, Port, TcpOpts) of
        {error, Reason} ->
            {stop, normal, {error, Reason}, ready, ready};
        {ok, Socket} ->
            EphPair = enacl:box_keypair(),
            case send_hello(Socket, EphPair, proplists:get_value(key, Options)) of
                ok ->
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, initiating, #{ from => From, socket => Socket, keys => EphPair }};
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

handle_info({tcp, S, Data}, Statename, #{ socket => S } = State) ->
    handle_packet(Data, Statename, State);
handle_info({tcp_closed, S}, Statename, # { socket => S } = State) ->
    handle_tcp_closed(Statename, State);
handle_info(Info, Statename, State) ->
    error_logger:info_msg("Unknown info msg ~p in state ~p", [Info, Statename]),
    {next_state, Statename, State}.

terminate(_Reason, _Statename, _State) ->
    ok.

code_change(_OldVsn, Statename, State, _Aux) ->
    {ok, Statename, State}.

%% Internal handlers
handle_packet(<<108,9,175,178,138,169,250,252, Pubkey:32/binary, Box/binary>>, accepting, S) ->
	todo;
handle_packet(<<28,69,220,185,65,192,227,246, Box/binary>>, initiating, State) ->
    %% Cookie packet
    <<EphPeerPublicKey:32/binary, K/binary>> = enacl:box_open(Box, 
%% Internal functions

hello_nonce() ->
    binary:copy(<<0>>, enacl:box_nonce_size()).

send_hello(Socket, #{ public := C, secret := Cs }, TargetKey) ->
    Box = enacl:box(binary:copy(<<0>>, 64), hello_nonce(), TargetKey, Cs),
    H = <<108,9,175,178,138,169,250,252, C:32/binary, Box/binary>>,
    gen_tcp:send(Socket, H).
    